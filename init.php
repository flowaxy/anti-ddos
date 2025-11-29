<?php
/**
 * Плагін Anti DDoS
 * 
 * Цей плагін захищає веб-сайт від DDoS атак, обмежуючи запити
 * з IP-адрес та блокування підозрілої активності.
 * 
 * @package AntiDdos
 * @version 1.0.0
 * @author Flowaxy Team
 */

declare(strict_types=1);

$rootDir = defined('ROOT_DIR') ? ROOT_DIR : dirname(__DIR__, 2);
require_once $rootDir . '/engine/core/support/base/BasePlugin.php';
require_once $rootDir . '/engine/core/support/helpers/UrlHelper.php';

// Підключаємо Logger для логування
if (!class_exists('Logger') && file_exists($rootDir . '/engine/infrastructure/logging/Logger.php')) {
    require_once $rootDir . '/engine/infrastructure/logging/Logger.php';
}

if (! function_exists('addHook')) {
    require_once $rootDir . '/engine/includes/functions.php';
}

// Завантажуємо ClassAutoloader для реєстрації класів
if (file_exists($rootDir . '/engine/core/system/ClassAutoloader.php')) {
    require_once $rootDir . '/engine/core/system/ClassAutoloader.php';
}

// Підключаємо SecurityHelper для перевірки авторизації
if (!class_exists('SecurityHelper') && file_exists($rootDir . '/engine/core/support/helpers/SecurityHelper.php')) {
    require_once $rootDir . '/engine/core/support/helpers/SecurityHelper.php';
}

// Підключаємо Session для перевірки сесії
if (!class_exists('Session') && file_exists($rootDir . '/engine/infrastructure/security/Session.php')) {
    require_once $rootDir . '/engine/infrastructure/security/Session.php';
}

// Завантажуємо AntiDdosService
$antiDdosServiceFile = dirname(__FILE__) . '/src/Services/AntiDdosService.php';
if (file_exists($antiDdosServiceFile)) {
    require_once $antiDdosServiceFile;
}

/**
 * Клас плагіна Anti DDoS
 * 
 * Відповідає за ініціалізацію плагіна, реєстрацію маршрутів,
 * пунктів меню та обробку запитів для захисту від DDoS.
 */
class AntiDdosPlugin extends BasePlugin
{
    private string $pluginDir;
    
    /** @var bool Захист від повторної перевірки запиту */
    private static bool $requestChecked = false;

    /**
     * Конструктор плагіна
     */
    public function __construct()
    {
        parent::__construct();
        $reflection = new ReflectionClass($this);
        $this->pluginDir = dirname($reflection->getFileName());
    }

    /**
     * Ініціалізація плагіна
     * 
     * Реєструє маршрути адмін-панелі, пункти меню та хуки для захисту від DDoS.
     */
    public function init(): void
    {
        // Реєстрація маршруту для налаштувань
        addHook('admin_register_routes', [$this, 'registerAdminRoute'], 10, 1);
        
        // Реєстрація пункту меню
        addFilter('admin_menu', [$this, 'registerAdminMenu'], 20);
        
        // Захист від DDoS (ранній хук з високим пріоритетом)
        addHook('handle_early_request', [$this, 'checkDdos'], 2);
    }

    /**
     * Реєстрація адмін-маршруту
     * 
     * @param mixed $router Роутер для реєстрації маршруту
     * @return void
     */
    public function registerAdminRoute($router): void
    {
        $pageFile = $this->pluginDir . '/src/admin/pages/AntiDdosAdminPage.php';
        if (file_exists($pageFile)) {
            // Реєстрація класу в автозавантажувачі
            if (isset($GLOBALS['engineAutoloader'])) {
                $autoloader = $GLOBALS['engineAutoloader'];
                if ($autoloader instanceof ClassAutoloader || 
                    (is_object($autoloader) && method_exists($autoloader, 'addClassMap'))) {
                    $autoloader->addClassMap([
                        'AntiDdosAdminPage' => $pageFile
                    ]);
                }
            }
            
            require_once $pageFile;
            if (class_exists('AntiDdosAdminPage')) {
                $router->add(['GET', 'POST'], 'anti-ddos', 'AntiDdosAdminPage');
            }
        }
    }

    /**
     * Реєстрація пункту меню в адмін-панелі
     * 
     * Додає пункт "Anti DDoS" до меню "Система"
     * 
     * @param array<int, array<string, mixed>> $menu Поточне меню адмін-панелі
     * @return array<int, array<string, mixed>> Оновлене меню
     */
    public function registerAdminMenu(array $menu): array
    {
        // Додаємо пункт до меню "Система"
        $found = false;
        foreach ($menu as &$item) {
            if (isset($item['page']) && $item['page'] === 'system') {
                if (!isset($item['submenu'])) {
                    $item['submenu'] = [];
                }
                $item['submenu'][] = [
                    'text' => 'Anti DDoS',
                    'icon' => 'fas fa-shield-alt',
                    'href' => UrlHelper::admin('anti-ddos'),
                    'page' => 'anti-ddos',
                    'order' => 20,
                    'permission' => null,
                ];
                $found = true;
                break;
            }
        }
        
        // Якщо меню "Система" не знайдено, створюємо його
        if (! $found) {
            $menu[] = [
                'text' => 'Система',
                'icon' => 'fas fa-server',
                'href' => '#',
                'page' => 'system',
                'order' => 60,
                'permission' => null,
                'submenu' => [
                    [
                        'text' => 'Anti DDoS',
                        'icon' => 'fas fa-shield-alt',
                        'href' => UrlHelper::admin('anti-ddos'),
                        'page' => 'anti-ddos',
                        'order' => 20,
                        'permission' => null,
                    ],
                ],
            ];
        }

        return $menu;
    }

    /**
     * Перевірка захисту від DDoS
     * 
     * Перевіряє запит на наявність паттернів DDoS атак та блокує при необхідності.
     * Ігнорує запити до адмін-панелі, API та від авторизованих користувачів.
     * 
     * @param mixed $handled Початкове значення (false = запит не оброблено) або масив [$handled, $context]
     * @param array<string, mixed>|null $context Контекст хука (якщо передається окремо)
     * @return bool true - якщо запит заблоковано, false - для продовження обробки
     */
    public function checkDdos(mixed $handled = false, ?array $context = null): bool
    {
        // Обробка випадку, коли передається масив [$handled, $context]
        if (is_array($handled) && count($handled) >= 1) {
            $context = $handled[1] ?? null;
            $handled = $handled[0] ?? false;
        }
        
        // Нормалізація значення
        $handled = (bool)$handled;
        
        // Захист від повторної перевірки
        if (self::$requestChecked) {
            return $handled;
        }

        try {
            $path = $_SERVER['REQUEST_URI'] ?? '/';
            
            // Ігноруємо запити до адмін-панелі, API та статичних файлів
            if (str_starts_with($path, '/admin') || 
                str_starts_with($path, '/api') ||
                $path === '/favicon.ico' ||
                str_starts_with($path, '/robots.txt') ||
                str_starts_with($path, '/sitemap') ||
                preg_match('/\.(ico|png|jpg|jpeg|gif|css|js|woff|woff2|ttf|svg)$/i', $path)) {
                self::$requestChecked = true;
                return $handled;
            }
            
            // Спочатку перевіряємо авторизацію
            $adminUserId = 0;
            if (function_exists('sessionManager')) {
                $session = sessionManager();
                $adminUserId = (int)($session->get('admin_user_id') ?? 0);
            }
            
            // Ігноруємо запити від авторизованих користувачів
            if ($adminUserId > 0) {
                self::$requestChecked = true;
                return $handled;
            }
            
            // Додаткова перевірка через SecurityHelper
            if (function_exists('SecurityHelper') && class_exists('SecurityHelper')) {
                if (method_exists('SecurityHelper', 'isAdminLoggedIn') && SecurityHelper::isAdminLoggedIn()) {
                    self::$requestChecked = true;
                    return $handled;
                }
            }
            
            // Отримуємо IP-адресу
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

            // Перевіряємо на DDoS атаку
            if (class_exists('AntiDdosService')) {
                $antiDdos = new AntiDdosService($this->getSlug());
                
                if ($antiDdos->isBlocked($ip)) {
                    self::$requestChecked = true;
                    $antiDdos->blockRequest($ip, $path);
                    return true;
                }
                
                // Перевіряємо швидкість запитів
                if ($antiDdos->checkRequestRate($ip)) {
                    self::$requestChecked = true;
                    $antiDdos->blockRequest($ip, $path);
                    return true;
                }
            }
        } catch (\Throwable $e) {
            if (function_exists('logger')) {
                logger()->logException($e, ['plugin' => 'anti-ddos', 'method' => 'checkDdos']);
            }
        }

        self::$requestChecked = true;
        return $handled;
    }

    /**
     * Встановлення плагіна (створення таблиць)
     * 
     * Створює необхідні таблиці в базі даних та встановлює налаштування за замовчуванням.
     */
    public function install(): void
    {
        try {
            $db = DatabaseHelper::getInstance();
            if (!$db || !$db->isAvailable()) {
                return;
            }

            // Перевіряємо, чи існує таблиця
            if (DatabaseHelper::tableExists('anti_ddos_logs')) {
                return; // Таблиця вже існує
            }

            // Таблиця логів захисту від DDoS
            $db->execute('
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

            // Таблиця відстеження запитів
            $db->execute('
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

            // Встановлюємо налаштування за замовчуванням
            $defaultSettings = [
                'enabled' => '1',
                'max_requests_per_minute' => '60',
                'max_requests_per_hour' => '1000',
                'block_duration_minutes' => '60',
                'whitelist_ips' => json_encode(['127.0.0.1', '::1'], JSON_UNESCAPED_UNICODE),
                'blacklist_ips' => json_encode([], JSON_UNESCAPED_UNICODE),
            ];

            foreach ($defaultSettings as $key => $value) {
                $this->setSetting($key, $value);
            }
        } catch (\Exception $e) {
            if (function_exists('logger')) {
                logger()->logException($e, ['plugin' => 'anti-ddos', 'action' => 'install']);
            }
        }
    }
}

return new AntiDdosPlugin();
