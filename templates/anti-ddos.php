<?php
/**
 * Шаблон сторінки налаштувань Anti DDoS
 */

// Визначаємо правильний шлях до компонентів адмін-панелі
$rootDir = defined('ROOT_DIR') ? ROOT_DIR : dirname(__DIR__, 4);
$componentsPath = $rootDir . '/engine/interface/admin-ui/components/';

?>

<!-- Сповіщення -->
<?php
if (! empty($message)) {
    include $componentsPath . 'alert.php';
    $type = $messageType ?? 'info';
    $dismissible = true;
}
?>

<?php
// Ініціалізація та нормалізація даних з render()
$pluginSettings = isset($antiDdosSettings) && is_array($antiDdosSettings) 
    ? $antiDdosSettings 
    : ['enabled' => '0', 'max_requests_per_minute' => '60', 'max_requests_per_hour' => '1000', 'block_duration_minutes' => '60', 'whitelist_ips' => [], 'blacklist_ips' => []];

$pluginStats = isset($antiDdosStats) && is_array($antiDdosStats) 
    ? $antiDdosStats 
    : ['today_blocks' => 0, 'total_blocks' => 0, 'top_ips' => []];

// Нормалізація налаштування enabled
$enabledValue = $pluginSettings['enabled'] ?? '0';
if (is_string($enabledValue)) {
    $enabledValue = trim($enabledValue);
} elseif (is_bool($enabledValue)) {
    $enabledValue = $enabledValue ? '1' : '0';
} elseif (is_int($enabledValue)) {
    $enabledValue = ($enabledValue === 1) ? '1' : '0';
} else {
    $enabledValue = '0';
}
$enabledSetting = ($enabledValue === '1') ? '1' : '0';

// Нормалізація списків IP
$whitelistIpsList = [];
if (!empty($pluginSettings['whitelist_ips'])) {
    if (is_array($pluginSettings['whitelist_ips'])) {
        $whitelistIpsList = $pluginSettings['whitelist_ips'];
    } elseif (is_string($pluginSettings['whitelist_ips'])) {
        $decoded = json_decode($pluginSettings['whitelist_ips'], true);
        if (is_array($decoded) && !empty($decoded)) {
            $whitelistIpsList = $decoded;
        }
    }
}

$blacklistIpsList = [];
if (!empty($pluginSettings['blacklist_ips'])) {
    if (is_array($pluginSettings['blacklist_ips'])) {
        $blacklistIpsList = $pluginSettings['blacklist_ips'];
    } elseif (is_string($pluginSettings['blacklist_ips'])) {
        $decoded = json_decode($pluginSettings['blacklist_ips'], true);
        if (is_array($decoded) && !empty($decoded)) {
            $blacklistIpsList = $decoded;
        }
    }
}

// Контент секції форми
ob_start();
?>
<div class="anti-ddos-page">
    <!-- Статистика -->
    <div class="row mb-4">
        <div class="col-md-4 mb-3">
            <div class="card border-left-danger h-100">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col">
                            <div class="text-xs font-weight-bold text-danger text-uppercase mb-1">
                                Заблоковано сьогодні
                            </div>
                            <div class="h4 mb-0 font-weight-bold text-gray-800">
                                <?= number_format($pluginStats['today_blocks'] ?? 0, 0, ',', ' ') ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-ban fa-2x text-danger opacity-25"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-left-warning h-100">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col">
                            <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                Всього заблоковано
                            </div>
                            <div class="h4 mb-0 font-weight-bold text-gray-800">
                                <?= number_format($pluginStats['total_blocks'] ?? 0, 0, ',', ' ') ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-shield-alt fa-2x text-warning opacity-25"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-4 mb-3">
            <div class="card border-left-info h-100">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col">
                            <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                Статус
                            </div>
                            <div class="h4 mb-0 font-weight-bold text-gray-800">
                                <?php 
                                $isEnabled = ($enabledSetting === '1');
                                echo $isEnabled ? '<span class="text-success">Активний</span>' : '<span class="text-muted">Неактивний</span>';
                                ?>
                            </div>
                        </div>
                        <div class="col-auto">
                            <i class="fas fa-toggle-<?= ($enabledSetting === '1') ? 'on' : 'off' ?> fa-2x text-info opacity-25"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Налаштування -->
    <div class="row mb-4">
        <div class="col-md-8 mb-3">
            <div class="card border-0">
                <div class="card-header bg-white border-bottom">
                    <h5 class="mb-0">Налаштування захисту</h5>
                </div>
                <div class="card-body">
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?= SecurityHelper::csrfToken() ?>">
                        
                        <div class="mb-4">
                            <?php
                            // Використовуємо компонент форми з ядра
                            $type = 'checkbox';
                            $name = 'enabled';
                            $label = 'Увімкнути захист від DDoS';
                            $value = $enabledSetting;
                            $helpText = 'Якщо увімкнено, запити, що перевищують ліміти швидкості, будуть заблоковані';
                            $id = 'enabled';
                            $attributes = [];
                            include $componentsPath . 'form-group.php';
                            ?>
                        </div>

                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="maxRequestsPerMinute" class="form-label fw-semibold">
                                    Максимум запитів на хвилину
                                </label>
                                <input type="number" class="form-control" id="maxRequestsPerMinute" 
                                       name="max_requests_per_minute" 
                                       value="<?= htmlspecialchars($pluginSettings['max_requests_per_minute'] ?? '60') ?>" 
                                       min="1" max="1000" required>
                                <small class="text-muted d-block mt-2">
                                    Максимальна кількість запитів, дозволена за хвилину з однієї IP-адреси
                                </small>
                            </div>
                            <div class="col-md-6">
                                <label for="maxRequestsPerHour" class="form-label fw-semibold">
                                    Максимум запитів на годину
                                </label>
                                <input type="number" class="form-control" id="maxRequestsPerHour" 
                                       name="max_requests_per_hour" 
                                       value="<?= htmlspecialchars($pluginSettings['max_requests_per_hour'] ?? '1000') ?>" 
                                       min="1" max="100000" required>
                                <small class="text-muted d-block mt-2">
                                    Максимальна кількість запитів, дозволена за годину з однієї IP-адреси
                                </small>
                            </div>
                        </div>

                        <div class="mb-3">
                            <label for="blockDurationMinutes" class="form-label fw-semibold">
                                Тривалість блокування (хвилини)
                            </label>
                            <input type="number" class="form-control" id="blockDurationMinutes" 
                                   name="block_duration_minutes" 
                                   value="<?= htmlspecialchars($pluginSettings['block_duration_minutes'] ?? '60') ?>" 
                                   min="1" max="1440" required>
                            <small class="text-muted d-block mt-2">
                                На скільки хвилин блокувати IP-адресу після перевищення лімітів швидкості
                            </small>
                        </div>

                        <div class="mb-3">
                            <label for="whitelistIps" class="form-label fw-semibold">
                                Білий список IP (один на рядок)
                            </label>
                            <textarea class="form-control" id="whitelistIps" name="whitelist_ips" rows="4" 
                                      placeholder="127.0.0.1&#10;::1"><?php 
                                if (!empty($whitelistIpsList) && is_array($whitelistIpsList)) {
                                    echo htmlspecialchars(implode("\n", $whitelistIpsList)); 
                                }
                            ?></textarea>
                            <small class="text-muted d-block mt-2">
                                IP-адреси, які ніколи не будуть заблоковані (наприклад, 127.0.0.1, ::1). Одна IP на рядок.
                            </small>
                        </div>

                        <div class="mb-3">
                            <label for="blacklistIps" class="form-label fw-semibold">
                                Чорний список IP (один на рядок)
                            </label>
                            <textarea class="form-control" id="blacklistIps" name="blacklist_ips" rows="4" 
                                      placeholder="192.168.1.100"><?php 
                                if (!empty($blacklistIpsList) && is_array($blacklistIpsList)) {
                                    echo htmlspecialchars(implode("\n", $blacklistIpsList)); 
                                }
                            ?></textarea>
                            <small class="text-muted d-block mt-2">
                                IP-адреси, які завжди будуть заблоковані. Одна IP на рядок.
                            </small>
                        </div>

                        <div class="d-flex justify-content-end gap-2">
                            <button type="submit" name="save_settings" value="1" class="btn btn-primary">
                                <i class="fas fa-save me-1"></i>Зберегти налаштування
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="col-md-4 mb-3">
            <div class="card border-0">
                <div class="card-header bg-white border-bottom">
                    <h5 class="mb-0">Топ заблокованих IP</h5>
                </div>
                <div class="card-body">
                    <?php if (empty($pluginStats['top_ips'])): ?>
                        <p class="text-muted mb-0">Немає даних</p>
                    <?php else: ?>
                        <div class="list-group list-group-flush">
                            <?php foreach ($pluginStats['top_ips'] as $index => $ipData): ?>
                                <div class="list-group-item px-0 py-2">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <div class="fw-semibold"><?= htmlspecialchars($ipData['ip_address']) ?></div>
                                            <small class="text-muted">
                                                <?= number_format($ipData['count'], 0, ',', ' ') ?> спроб
                                            </small>
                                        </div>
                                        <span class="badge bg-danger"><?= $index + 1 ?></span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Інформація -->
    <div class="card border-0">
        <div class="card-header bg-white border-bottom">
            <h5 class="mb-0">Про захист від DDoS</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h6 class="fw-semibold mb-3">Як це працює:</h6>
                    <ul class="mb-0">
                        <li>Система відстежує кількість запитів з кожної IP-адреси</li>
                        <li>Запити, що перевищують ліміти швидкості, блокуються</li>
                        <li>Заблоковані IP отримують відповідь 429 Too Many Requests</li>
                        <li>Всі заблоковані запити логуються в базу даних</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6 class="fw-semibold mb-3">Що робиться:</h6>
                    <ul class="mb-0">
                        <li>Обмеження швидкості: ліміти запитів на хвилину/годину</li>
                        <li>Автоматичне блокування підозрілих IP</li>
                        <li>Адмін-панель та API завжди доступні</li>
                        <li>Керування білим та чорним списком IP</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
$sectionContent = ob_get_clean();

// Використовуємо компонент секції контенту
$title = '';
$icon = '';
$content = $sectionContent;
$classes = ['anti-ddos-page'];
include $componentsPath . 'content-section.php';
?>