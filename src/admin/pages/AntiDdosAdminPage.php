<?php

/**
 * Сторінка налаштувань Anti DDoS
 */

declare(strict_types=1);

$rootDir = defined('ROOT_DIR') ? ROOT_DIR : dirname(__DIR__, 5);
$engineDir = $rootDir . '/engine';

require_once $engineDir . '/interface/admin-ui/includes/AdminPage.php';


if (!class_exists('Response') && file_exists($engineDir . '/interface/http/controllers/Response.php')) {
    require_once $engineDir . '/interface/http/controllers/Response.php';
}

if (!class_exists('SecurityHelper') && file_exists($engineDir . '/core/support/helpers/SecurityHelper.php')) {
    require_once $engineDir . '/core/support/helpers/SecurityHelper.php';
}

// Завантажуємо AntiDdosService
$serviceFile = dirname(__DIR__, 2) . '/Services/AntiDdosService.php';
if (file_exists($serviceFile)) {
    require_once $serviceFile;
}

class AntiDdosAdminPage extends AdminPage
{
    private string $pluginDir;
    private ?AntiDdosService $antiDdosService = null;

    public function __construct()
    {
        parent::__construct();

        // Перевірка прав доступу
        if (! function_exists('current_user_can') || ! current_user_can('admin.access')) {
            Response::redirectStatic(UrlHelper::admin('dashboard'));
            exit;
        }

        // Визначаємо шлях до директорії плагіна
        $this->pluginDir = dirname(__DIR__, 3);

        $this->pageTitle = 'Anti DDoS - Flowaxy CMS';
        $this->templateName = 'anti-ddos';

        $this->setPageHeader(
            'Anti DDoS',
            'Налаштування захисту від DDoS атак',
            'fas fa-shield-alt'
        );

        // Додаємо хлібні крихти
        $this->setBreadcrumbs([
            ['title' => 'Головна', 'url' => UrlHelper::admin('dashboard')],
            ['title' => 'Anti DDoS'],
        ]);

        // Ініціалізуємо сервіс
        if (class_exists('AntiDdosService')) {
            try {
                $this->antiDdosService = new AntiDdosService('anti-ddos');
            } catch (\Throwable $e) {
                logger()->logException($e, ['plugin' => 'anti-ddos', 'action' => 'init']);
            }
        }

        // Підключаємо CSS
        $this->additionalCSS[] = $this->pluginAsset('styles/anti-ddos.css');
    }

    /**
     * Отримання URL до ресурсів плагіна
     */
    private function pluginAsset(string $path): string
    {
        $relativePath = 'plugins/anti-ddos/assets/' . ltrim($path, '/');
        $absolutePath = $this->pluginDir . '/assets/' . ltrim($path, '/');
        $version = file_exists($absolutePath) ? substr(md5_file($absolutePath), 0, 8) : substr((string)time(), -8);

        return UrlHelper::base($relativePath) . '?v=' . $version;
    }

    /**
     * Отримання шляху до шаблонів плагіна
     */
    protected function getTemplatePath()
    {
        return $this->pluginDir . '/templates/';
    }

    public function handle(): void
    {
        if (!$this->antiDdosService) {
            $this->setMessage('Помилка: сервіс Anti DDoS недоступний', 'danger');
            $this->render([]);
            return;
        }

        // Обробка збереження налаштувань
        if ($this->isMethod('POST') && $this->post('save_settings')) {
            $this->handleSaveSettings();
            return;
        }

        // Обробка очищення логів
        if ($this->isMethod('POST') && $this->post('clear_logs')) {
            $this->handleClearLogs();
            return;
        }

        // Отримуємо статистику та налаштування
        try {
            $this->antiDdosService = new AntiDdosService('anti-ddos');
            $settings = $this->antiDdosService->getSettings();
            $stats = $this->antiDdosService->getStats();

            $this->render([
                'antiDdosSettings' => $settings,
                'antiDdosStats' => $stats,
            ]);
        } catch (\Throwable $e) {
            logger()->logException($e, ['plugin' => 'anti-ddos', 'action' => 'render']);
            $this->setMessage('Помилка завантаження налаштувань: ' . $e->getMessage(), 'danger');
            $this->render([
                'antiDdosSettings' => ['enabled' => '0', 'max_requests_per_minute' => '60', 'max_requests_per_hour' => '1000', 'block_duration_minutes' => '60', 'whitelist_ips' => [], 'blacklist_ips' => []],
                'antiDdosStats' => ['today_blocks' => 0, 'total_blocks' => 0, 'top_ips' => []],
            ]);
        }
    }

    /**
     * Збереження налаштувань
     */
    private function handleSaveSettings(): void
    {
        if (!$this->verifyCsrf()) {
            $this->setMessage('Помилка безпеки: невірний CSRF токен', 'danger');
            return;
        }

        try {
            // Отримуємо значення checkbox
            $hasEnabled = $this->request()->has('enabled') || isset($_POST['enabled']);
            $enabled = $hasEnabled && ($this->post('enabled', '0') === '1') ? '1' : '0';
            
            $maxRequestsPerMinute = (int)$this->post('max_requests_per_minute', 60);
            $maxRequestsPerHour = (int)$this->post('max_requests_per_hour', 1000);
            $blockDurationMinutes = (int)$this->post('block_duration_minutes', 60);
            
            // Обробляємо білий список IP
            $whitelistIps = [];
            $whitelistIpsRaw = $this->post('whitelist_ips', '');
            if (!empty($whitelistIpsRaw)) {
                $ipsList = explode("\n", $whitelistIpsRaw);
                foreach ($ipsList as $ip) {
                    $ip = trim($ip);
                    if (!empty($ip)) {
                        $whitelistIps[] = $ip;
                    }
                }
            }
            
            // Обробляємо чорний список IP
            $blacklistIps = [];
            $blacklistIpsRaw = $this->post('blacklist_ips', '');
            if (!empty($blacklistIpsRaw)) {
                $ipsList = explode("\n", $blacklistIpsRaw);
                foreach ($ipsList as $ip) {
                    $ip = trim($ip);
                    if (!empty($ip)) {
                        $blacklistIps[] = $ip;
                    }
                }
            }

            $settings = [
                'enabled' => $enabled,
                'max_requests_per_minute' => (string)$maxRequestsPerMinute,
                'max_requests_per_hour' => (string)$maxRequestsPerHour,
                'block_duration_minutes' => (string)$blockDurationMinutes,
                'whitelist_ips' => $whitelistIps,
                'blacklist_ips' => $blacklistIps,
            ];

            $result = $this->antiDdosService->saveSettings($settings);

            if ($result) {
                // Оновлюємо сервіс для завантаження нових налаштувань
                $this->antiDdosService = new AntiDdosService('anti-ddos');
                logger()->logInfo('Anti DDoS налаштування збережено', [
                    'enabled' => $enabled,
                    'max_requests_per_minute' => $maxRequestsPerMinute,
                ]);
                $this->setMessage('Налаштування успішно збережено', 'success');
            } else {
                logger()->logWarning('Помилка збереження налаштувань Anti DDoS');
                $this->setMessage('Помилка збереження налаштувань', 'danger');
            }
        } catch (\Throwable $e) {
            logger()->logException($e, ['plugin' => 'anti-ddos', 'action' => 'save_settings']);
            $this->setMessage('Помилка: ' . $e->getMessage(), 'danger');
        }

        $this->redirect('anti-ddos');
    }

    /**
     * Очистка логів
     */
    private function handleClearLogs(): void
    {
        if (!$this->verifyCsrf()) {
            $this->setMessage('Помилка безпеки: невірний CSRF токен', 'danger');
            $this->redirect('anti-ddos');
            return;
        }

        try {
            if ($this->antiDdosService) {
                if ($this->antiDdosService->clearLogs()) {
                    logger()->logInfo('Anti DDoS логи очищено');
                    $this->setMessage('Логи успішно очищено', 'success');
                } else {
                    logger()->logWarning('Помилка очищення логів Anti DDoS');
                    $this->setMessage('Помилка очищення логів. Перевірте логи.', 'danger');
                }
            } else {
                $this->setMessage('Помилка: сервіс Anti DDoS недоступний', 'danger');
            }
        } catch (\Exception $e) {
            logger()->logError('Anti DDoS помилка очищення логів', ['error' => $e->getMessage()]);
            $this->setMessage('Помилка очищення логів: ' . $e->getMessage(), 'danger');
        }

        $this->redirect('anti-ddos');
    }
}
