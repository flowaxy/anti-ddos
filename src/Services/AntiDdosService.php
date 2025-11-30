<?php

/**
 * Сервіс Anti DDoS
 *
 * Відповідає за логіку захисту від DDoS атак,
 * обмеження швидкості запитів та керування блокуванням IP.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../../../engine/core/support/helpers/DatabaseHelper.php';
require_once __DIR__ . '/../../../../engine/infrastructure/persistence/DatabaseInterface.php';

// Підключаємо functions.php для доступу до TimezoneManager та helper функцій
$rootDir = defined('ROOT_DIR') ? ROOT_DIR : dirname(__DIR__, 4);
$functionsFile = $rootDir . '/engine/core/support/functions.php';
if (file_exists($functionsFile)) {
    require_once $functionsFile;
}

// Підключаємо Logger для логування
if (!class_exists('Logger')) {
    $loggerFile = $rootDir . '/engine/infrastructure/logging/Logger.php';
    if (file_exists($loggerFile)) {
        require_once $loggerFile;
    }
}

class AntiDdosService
{
    private ?DatabaseInterface $db = null;
    private string $pluginSlug;
    private bool $enabled = false;
    private int $maxRequestsPerMinute = 60;
    private int $maxRequestsPerHour = 1000;
    private int $blockDurationMinutes = 60;
    private array $whitelistIps = [];
    private array $blacklistIps = [];
    
    private static array $blockedRequests = [];

    public function __construct(string $pluginSlug = 'anti-ddos')
    {
        $this->pluginSlug = $pluginSlug;
        try {
            $this->db = DatabaseHelper::getInstance();
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка з\'єднання з базою даних - ' . $e->getMessage(), ['exception' => $e]);
        }

        $this->loadSettings();
    }

    /**
     * Завантаження налаштувань плагіна з бази даних
     */
    public function loadSettings(): void
    {
        if (!$this->db) {
            return;
        }

        try {
            // Очищаємо кеш налаштувань плагіна перед завантаженням
            if (function_exists('cache_forget')) {
                cache_forget('plugin_settings_' . $this->pluginSlug);
            }
            
            $rows = $this->db->getAll(
                'SELECT setting_key, setting_value FROM plugin_settings WHERE plugin_slug = ? ORDER BY setting_key',
                [$this->pluginSlug]
            );
            
            $settings = [];
            foreach ($rows as $row) {
                if (isset($row['setting_key']) && isset($row['setting_value'])) {
                    $settings[$row['setting_key']] = $row['setting_value'];
                }
            }

            // Завантажуємо налаштування enabled
            $enabledValue = $settings['enabled'] ?? '0';
            if (is_string($enabledValue)) {
                $enabledValue = trim($enabledValue);
            }
            $this->enabled = ($enabledValue === '1');
            
            // Завантажуємо ліміти швидкості
            $this->maxRequestsPerMinute = (int)($settings['max_requests_per_minute'] ?? 60);
            $this->maxRequestsPerHour = (int)($settings['max_requests_per_hour'] ?? 1000);
            $this->blockDurationMinutes = (int)($settings['block_duration_minutes'] ?? 60);
            
            // Завантажуємо списки IP
            $this->whitelistIps = [];
            if (!empty($settings['whitelist_ips'])) {
                $decoded = json_decode($settings['whitelist_ips'], true);
                if (is_array($decoded)) {
                    $this->whitelistIps = array_map('trim', $decoded);
                }
            }
            
            $this->blacklistIps = [];
            if (!empty($settings['blacklist_ips'])) {
                $decoded = json_decode($settings['blacklist_ips'], true);
                if (is_array($decoded)) {
                    $this->blacklistIps = array_map('trim', $decoded);
                }
            }
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка завантаження налаштувань - ' . $e->getMessage(), ['exception' => $e]);
            $this->enabled = false;
        }
    }

    /**
     * Отримання часового поясу з БД через TimezoneManager
     * 
     * Використовує TimezoneManager з ядра, який завантажує timezone з БД
     * 
     * @return string Часовий пояс (наприклад, "Europe/Kyiv")
     */
    private function getTimezoneFromSettings(): string
    {
        // Використовуємо TimezoneManager з ядра, який завантажує timezone з БД
        if (function_exists('getTimezoneFromDatabase')) {
            return getTimezoneFromDatabase();
        }
        
        // Fallback на системний timezone, якщо функція недоступна
        return date_default_timezone_get() ?: 'Europe/Kyiv';
    }

    /**
     * Перевіряє існування таблиць і створює їх, якщо вони відсутні
     *
     * @return bool True, якщо таблиці існують або були успішно створені, false у разі помилки
     */
    private function ensureTablesExist(): bool
    {
        if (!$this->db) {
            return false;
        }

        try {
            // Перевіряємо, чи існує таблиця логів
            if (!DatabaseHelper::tableExists('anti_ddos_logs')) {
                $this->db->execute('
                    CREATE TABLE IF NOT EXISTS anti_ddos_logs (
                        id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                        ip_address VARCHAR(45) NOT NULL,
                        url VARCHAR(500),
                        blocked_at DATETIME NOT NULL,
                        created_at DATETIME NOT NULL,
                        PRIMARY KEY (id),
                        KEY idx_blocked_at (blocked_at),
                        KEY idx_ip_address (ip_address)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                ');
            }

            // Перевіряємо, чи існує таблиця запитів
            if (!DatabaseHelper::tableExists('anti_ddos_requests')) {
                $this->db->execute('
                    CREATE TABLE IF NOT EXISTS anti_ddos_requests (
                        id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                        ip_address VARCHAR(45) NOT NULL,
                        request_count INT(11) UNSIGNED NOT NULL DEFAULT 1,
                        first_request_at DATETIME NOT NULL,
                        last_request_at DATETIME NOT NULL,
                        PRIMARY KEY (id),
                        UNIQUE KEY idx_ip_address (ip_address),
                        KEY idx_last_request_at (last_request_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                ');
            }

            return true;
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Не вдалося створити таблиці - ' . $e->getMessage(), ['exception' => $e]);
            return false;
        }
    }

    /**
     * Перевіряє, чи заблокована IP-адреса
     *
     * @param string $ip IP-адреса
     * @return bool True, якщо IP заблокована
     */
    public function isBlocked(string $ip): bool
    {
        if (!$this->enabled || !$this->db) {
            return false;
        }

        // Спочатку перевіряємо білий список
        if (in_array($ip, $this->whitelistIps, true)) {
            return false;
        }

        // Перевіряємо чорний список
        if (in_array($ip, $this->blacklistIps, true)) {
            return true;
        }

        if (!$this->ensureTablesExist()) {
            return false;
        }

        try {
            // Отримуємо timezone з БД через TimezoneManager
            $timezone = $this->getTimezoneFromSettings();
            $tz = new \DateTimeZone($timezone);
            $now = new \DateTime('now', $tz);
            
            // Перевіряємо, чи заблокована IP в логах в межах тривалості блокування
            $blockUntil = clone $now;
            $blockUntil->modify('-' . $this->blockDurationMinutes . ' minutes');
            $blockUntilStr = $blockUntil->format('Y-m-d H:i:s');

            $blocked = $this->db->getValue(
                'SELECT COUNT(*) FROM anti_ddos_logs WHERE ip_address = ? AND blocked_at > ?',
                [$ip, $blockUntilStr]
            );

            return (int)$blocked > 0;
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка перевірки заблокованої IP - ' . $e->getMessage(), ['exception' => $e]);
            return false;
        }
    }

    /**
     * Перевіряє швидкість запитів для IP-адреси
     *
     * @param string $ip IP-адреса
     * @return bool True, якщо ліміт швидкості перевищено
     */
    public function checkRequestRate(string $ip): bool
    {
        if (!$this->enabled || !$this->db) {
            return false;
        }

        // Перевіряємо білий список
        if (in_array($ip, $this->whitelistIps, true)) {
            return false;
        }

        // Перевіряємо чорний список
        if (in_array($ip, $this->blacklistIps, true)) {
            return true;
        }

        if (!$this->ensureTablesExist()) {
            return false;
        }

        try {
            // Отримуємо timezone з БД через TimezoneManager
            $timezone = $this->getTimezoneFromSettings();
            $tz = new \DateTimeZone($timezone);
            $now = new \DateTime('now', $tz);
            $nowStr = $now->format('Y-m-d H:i:s');

            // Отримуємо або створюємо запис запиту
            $requestRecord = $this->db->getRow(
                'SELECT * FROM anti_ddos_requests WHERE ip_address = ?',
                [$ip]
            );

            if (!$requestRecord) {
                // Перший запит з цієї IP
                $this->db->execute(
                    'INSERT INTO anti_ddos_requests (ip_address, request_count, first_request_at, last_request_at) VALUES (?, 1, ?, ?)',
                    [$ip, $nowStr, $nowStr]
                );
                return false;
            }

            $requestCount = (int)($requestRecord['request_count'] ?? 1);
            $firstRequestAt = $requestRecord['first_request_at'] ?? $nowStr;
            $lastRequestAtStr = $requestRecord['last_request_at'] ?? $nowStr;
            $lastRequestAt = new \DateTime($lastRequestAtStr, $tz);
            $firstRequestAtDt = new \DateTime($firstRequestAt, $tz);

            // Обчислюємо різницю часу
            $secondsSinceLast = $now->getTimestamp() - $lastRequestAt->getTimestamp();
            $minutesSinceFirst = (int)(($now->getTimestamp() - $firstRequestAtDt->getTimestamp()) / 60);

            // Скидаємо годинний лічильник, якщо пройшло більше 1 години
            if ($minutesSinceFirst >= 60) {
                $this->db->execute(
                    'UPDATE anti_ddos_requests SET request_count = 1, first_request_at = ?, last_request_at = ? WHERE ip_address = ?',
                    [$nowStr, $nowStr, $ip]
                );
                return false;
            }

            // Скидаємо хвилинний лічильник, якщо пройшло більше 1 хвилини з останнього запиту
            if ($secondsSinceLast >= 60) {
                // Залишаємо first_request_at для годинного відстеження, скидаємо тільки хвилинний лічильник
                $this->db->execute(
                    'UPDATE anti_ddos_requests SET request_count = 1, last_request_at = ? WHERE ip_address = ?',
                    [$nowStr, $ip]
                );
                return false;
            }

            // Збільшуємо лічильник запитів
            $newCount = $requestCount + 1;
            
            // Оновлюємо запис запиту
            $this->db->execute(
                'UPDATE anti_ddos_requests SET request_count = ?, last_request_at = ? WHERE ip_address = ?',
                [$newCount, $nowStr, $ip]
            );

            // Перевіряємо хвилинний ліміт (запити за останню хвилину)
            if ($secondsSinceLast < 60 && $newCount > $this->maxRequestsPerMinute) {
                return true;
            }

            // Перевіряємо годинний ліміт (запити за останню годину)
            if ($minutesSinceFirst < 60 && $newCount > $this->maxRequestsPerHour) {
                return true;
            }

            return false;
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка перевірки швидкості запитів - ' . $e->getMessage(), ['exception' => $e]);
            return false;
        }
    }

    /**
     * Блокує запит з IP-адреси та логує його
     *
     * @param string $ip IP-адреса
     * @param string|null $url URL запиту
     */
    public function blockRequest(string $ip, ?string $url = null): void
    {
        // Генеруємо унікальний ключ для запиту
        $ipValue = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        $urlValue = $url ?? ($_SERVER['REQUEST_URI'] ?? '/');
        $requestKey = md5($ipValue . '|' . $urlValue);
        
        // Якщо цей запит вже був заблокований у поточному запиті, нічого не робимо
        if (isset(self::$blockedRequests[$requestKey])) {
            return;
        }
        
        // Позначаємо, що цей запит вже обробляється
        self::$blockedRequests[$requestKey] = true;
        
        // Логуємо спробу блокування
        if ($this->db && $this->ensureTablesExist()) {
            try {
                // Отримуємо timezone з БД через TimezoneManager
                $timezone = $this->getTimezoneFromSettings();
                $now = new \DateTime('now', new \DateTimeZone($timezone));
                $blockedAt = $now->format('Y-m-d H:i:s');
                
                // Встановлюємо created_at явно, щоб використовувати той самий час, що і blocked_at
                $this->db->insert(
                    'INSERT INTO anti_ddos_logs (ip_address, url, blocked_at, created_at) VALUES (?, ?, ?, ?)',
                    [
                        $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'),
                        $url ?? ($_SERVER['REQUEST_URI'] ?? '/'),
                        $blockedAt,
                        $blockedAt, // Використовуємо той самий час для created_at
                    ]
                );
            } catch (\Exception $e) {
                logger()->logError('AntiDdosService: Помилка логування - ' . $e->getMessage(), ['exception' => $e]);
            }
        }

        // Відправляємо 429 Too Many Requests
        http_response_code(429);
        header('Content-Type: text/html; charset=utf-8');
        header('Retry-After: ' . ($this->blockDurationMinutes * 60));
        
        echo '<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Занадто багато запитів</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #dc3545;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>429 - Занадто багато запитів</h1>
        <p>Занадто багато запитів з вашої IP-адреси. Будь ласка, спробуйте пізніше.</p>
    </div>
</body>
</html>';
        exit;
    }

    /**
     * Отримання статистики захисту
     *
     * @param string|null $dateFrom Початкова дата для фільтрації
     * @param string|null $dateTo Кінцева дата для фільтрації
     * @return array Статистика, що включає загальні блокування, блокування сьогодні та топ IP
     */
    public function getStats(?string $dateFrom = null, ?string $dateTo = null): array
    {
        if (!$this->db) {
            return [];
        }

        if (!$this->ensureTablesExist()) {
            return [];
        }

        try {
            $sql = 'SELECT COUNT(*) as total_blocks FROM anti_ddos_logs WHERE 1=1';
            $params = [];

            if ($dateFrom && $dateTo) {
                $sql .= ' AND DATE(blocked_at) BETWEEN ? AND ?';
                $params[] = $dateFrom;
                $params[] = $dateTo;
            }

            $total = (int)($this->db->getValue($sql, $params) ?: 0);

            // Отримуємо timezone з БД через TimezoneManager
            $timezone = $this->getTimezoneFromSettings();
            $tz = new \DateTimeZone($timezone);
            $todayDate = new \DateTime('today', $tz);
            $todayDateStr = $todayDate->format('Y-m-d');
            
            // Порівнюємо дати (дані зберігаються в часовому поясі з БД)
            $todayBlocks = (int)($this->db->getValue(
                "SELECT COUNT(*) FROM anti_ddos_logs WHERE DATE(blocked_at) = ?",
                [$todayDateStr]
            ) ?: 0);

            // Топ заблокованих IP
            $topIps = $this->db->getAll('
                SELECT ip_address, COUNT(*) as count 
                FROM anti_ddos_logs 
                GROUP BY ip_address 
                ORDER BY count DESC 
                LIMIT 10
            ');

            return [
                'total_blocks' => $total,
                'today_blocks' => $todayBlocks,
                'top_ips' => $topIps,
            ];
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка отримання статистики - ' . $e->getMessage(), ['exception' => $e]);
            return [];
        }
    }

    /**
     * Отримання поточних налаштувань плагіна
     * Примусово перезавантажує налаштування з бази даних перед поверненням.
     *
     * @return array Асоціативний масив налаштувань
     */
    public function getSettings(): array
    {
        $enabled = '0';
        $maxRequestsPerMinute = 60;
        $maxRequestsPerHour = 1000;
        $blockDurationMinutes = 60;
        $whitelistIps = [];
        $blacklistIps = [];
        
        if (!$this->db) {
            return [
                'enabled' => $enabled,
                'max_requests_per_minute' => (string)$maxRequestsPerMinute,
                'max_requests_per_hour' => (string)$maxRequestsPerHour,
                'block_duration_minutes' => (string)$blockDurationMinutes,
                'whitelist_ips' => $whitelistIps,
                'blacklist_ips' => $blacklistIps,
            ];
        }

        try {
            // Очищаємо кеш перед завантаженням
            if (function_exists('cache_forget')) {
                cache_forget('plugin_settings_' . $this->pluginSlug);
            }

            $rows = $this->db->getAll(
                'SELECT setting_key, setting_value FROM plugin_settings WHERE plugin_slug = ?',
                [$this->pluginSlug]
            );
            
            foreach ($rows as $row) {
                $key = $row['setting_key'] ?? '';
                $value = $row['setting_value'] ?? '';
                
                if ($key === 'enabled') {
                    $value = trim((string)$value);
                    $enabled = ($value === '1') ? '1' : '0';
                } elseif ($key === 'max_requests_per_minute') {
                    $maxRequestsPerMinute = (int)$value;
                } elseif ($key === 'max_requests_per_hour') {
                    $maxRequestsPerHour = (int)$value;
                } elseif ($key === 'block_duration_minutes') {
                    $blockDurationMinutes = (int)$value;
                } elseif ($key === 'whitelist_ips') {
                    if (!empty($value) && $value !== '[]' && $value !== 'null') {
                        $decoded = json_decode($value, true);
                        if (is_array($decoded)) {
                            $whitelistIps = $decoded;
                        }
                    }
                } elseif ($key === 'blacklist_ips') {
                    if (!empty($value) && $value !== '[]' && $value !== 'null') {
                        $decoded = json_decode($value, true);
                        if (is_array($decoded)) {
                            $blacklistIps = $decoded;
                        }
                    }
                }
            }
            
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Не вдалося завантажити налаштування з БД - ' . $e->getMessage(), ['exception' => $e]);
        }
        
        return [
            'enabled' => $enabled,
            'max_requests_per_minute' => (string)$maxRequestsPerMinute,
            'max_requests_per_hour' => (string)$maxRequestsPerHour,
            'block_duration_minutes' => (string)$blockDurationMinutes,
            'whitelist_ips' => $whitelistIps,
            'blacklist_ips' => $blacklistIps,
        ];
    }

    /**
     * Збереження налаштувань плагіна в базу даних
     *
     * @param array $settings Асоціативний масив налаштувань для збереження
     * @return bool True, якщо налаштування успішно збережено, false у разі помилки
     */
    public function saveSettings(array $settings): bool
    {
        if (!$this->db) {
            return false;
        }

        try {
            foreach ($settings as $key => $value) {
                if ($key === 'whitelist_ips' && is_array($value)) {
                    $value = json_encode($value, JSON_UNESCAPED_UNICODE);
                } elseif ($key === 'blacklist_ips' && is_array($value)) {
                    $value = json_encode($value, JSON_UNESCAPED_UNICODE);
                } elseif ($key === 'enabled') {
                    $value = ($value === '1' || $value === 1 || $value === true || $value === 'true') ? '1' : '0';
                }

                $this->db->execute(
                    'INSERT INTO plugin_settings (plugin_slug, setting_key, setting_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)',
                    [$this->pluginSlug, $key, (string)$value]
                );
            }
            
            if (function_exists('cache_forget')) {
                cache_forget('plugin_settings_' . $this->pluginSlug);
            }

            // Перезавантажуємо налаштування після збереження
            $this->loadSettings();

            return true;
        } catch (\Throwable $e) {
            logger()->logException($e, ['method' => 'saveSettings']);
            return false;
        }
    }

    /**
     * Очищення всіх логів захисту з бази даних
     *
     * @return bool True, якщо логи успішно очищено, false у разі помилки
     */
    public function clearLogs(): bool
    {
        if (!$this->db) {
            return false;
        }

        if (!$this->ensureTablesExist()) {
            return false;
        }

        try {
            $this->db->execute('TRUNCATE TABLE anti_ddos_logs');
            $this->db->execute('TRUNCATE TABLE anti_ddos_requests');
            return true;
        } catch (\Exception $e) {
            logger()->logError('AntiDdosService: Помилка очищення логів - ' . $e->getMessage(), ['exception' => $e]);
            return false;
        }
    }
}
