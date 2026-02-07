<?php
/**
 * Plugin Name: Accolades Guard
 * Description: Hardening and integrity monitoring for WordPress.
 * Author: Luc Constantin
 * Version: 1.1.2
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Accolades_Guard {

    const OPTION_KEY   = 'accolades_guard_options';
    const BASELINE_KEY = 'accolades_guard_baseline';
    const CRON_HOOK    = 'accolades_guard_daily_integrity_check';

    public static function init(): void {
        // Admin UI
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'admin_assets']);

        // Allow custom cron intervals
        add_filter('cron_schedules', [__CLASS__, 'cron_schedules']);

        // Core protections
        add_filter('xmlrpc_methods', [__CLASS__, 'filter_xmlrpc_methods']);
        add_filter('wp_headers', [__CLASS__, 'filter_wp_headers']);
        add_action('pre_comment_on_post', [__CLASS__, 'block_comments_early'], 1);

        add_action('init', [__CLASS__, 'block_suspicious_query_strings']);
        add_filter('user_has_cap', [__CLASS__, 'restrict_file_edit_caps'], 10, 4);
        add_action('template_redirect', [__CLASS__, 'frontend_signature_buffer']);

        // Integrity monitor
        add_action(self::CRON_HOOK, [__CLASS__, 'run_integrity_check']);
    }

    public static function activate(): void {
        self::ensure_cron_state(true);
    }

    public static function deactivate(): void {
        wp_clear_scheduled_hook(self::CRON_HOOK);
    }

    public static function defaults(): array {
        return [
            // Comments + pingbacks
            'disable_pingbacks'         => 1,
            'block_public_comments'     => 1,
            'allow_admin_comments_only' => 0,

            // Hardening
            'block_suspicious_qs'       => 1,
            'disable_file_editors'      => 1,

            // Signature
            'frontend_signature'        => 1,
            'signature_text'            => 'Hey, thank you for checking the code. This is Luc, the developer that built this website. Feel free to contact me at accolades.dev@gmail.com.',

            // Integrity
            'integrity_monitor'         => 1,
            'integrity_scope'           => 'core', // core | core_plugins_themes
            'integrity_email'           => '',
            'integrity_last_run'        => '',

            // Schedule (default 24h)
            'integrity_schedule'        => 'daily', // daily = 24h default
        ];
    }

    public static function get_options(): array {
        $saved = get_option(self::OPTION_KEY, []);
        return wp_parse_args(is_array($saved) ? $saved : [], self::defaults());
    }

    public static function enabled(string $key): bool {
        $opts = self::get_options();
        return !empty($opts[$key]);
    }

    /* =========================================================
     * Admin UI
     * ========================================================= */

    // Top-level menu
    public static function admin_menu(): void {
        add_menu_page(
            'Accolades Guard',
            'Accolades Guard',
            'manage_options',
            'accolades-guard',
            [__CLASS__, 'render_settings_page'],
            'dashicons-shield-alt',
            58
        );
    }

    public static function admin_assets(string $hook): void {
        if ($hook !== 'toplevel_page_accolades-guard') {
            return;
        }

        wp_enqueue_style(
            'accolades-guard-admin',
            plugin_dir_url(__FILE__) . 'assets/admin.css',
            [],
            '1.1.2'
        );

        wp_enqueue_script(
            'accolades-guard-admin',
            plugin_dir_url(__FILE__) . 'assets/admin.js',
            ['jquery'],
            '1.1.2',
            true
        );
    }

    public static function register_settings(): void {
        register_setting(self::OPTION_KEY, self::OPTION_KEY, [
            'type'              => 'array',
            'sanitize_callback' => [__CLASS__, 'sanitize_options'],
            'default'           => self::defaults(),
        ]);

        // Keep cron aligned when admin loads
        add_action('admin_init', function () {
            self::ensure_cron_state(false);
        }, 99);
    }

    public static function sanitize_options($input): array {
        $defaults = self::defaults();
        $prev     = self::get_options();
        $out      = [];

        $out['disable_pingbacks']         = !empty($input['disable_pingbacks']) ? 1 : 0;
        $out['block_public_comments']     = !empty($input['block_public_comments']) ? 1 : 0;
        $out['allow_admin_comments_only'] = !empty($input['allow_admin_comments_only']) ? 1 : 0;

        $out['block_suspicious_qs']       = !empty($input['block_suspicious_qs']) ? 1 : 0;
        $out['disable_file_editors']      = !empty($input['disable_file_editors']) ? 1 : 0;

        $out['frontend_signature']        = !empty($input['frontend_signature']) ? 1 : 0;

        $sig = isset($input['signature_text']) ? (string) $input['signature_text'] : $defaults['signature_text'];
        $sig = wp_strip_all_tags($sig);
        $out['signature_text'] = $sig !== '' ? $sig : $defaults['signature_text'];

        $out['integrity_monitor'] = !empty($input['integrity_monitor']) ? 1 : 0;

        $scope = isset($input['integrity_scope']) ? (string) $input['integrity_scope'] : $defaults['integrity_scope'];
        $out['integrity_scope'] = in_array($scope, ['core', 'core_plugins_themes'], true) ? $scope : $defaults['integrity_scope'];

        $email = isset($input['integrity_email']) ? sanitize_email((string) $input['integrity_email']) : '';
        $out['integrity_email'] = $email;

        $out['integrity_last_run'] = $prev['integrity_last_run'] ?? '';

        // Schedule sanitize
        $schedule = isset($input['integrity_schedule']) ? (string) $input['integrity_schedule'] : $defaults['integrity_schedule'];
        $allowed  = ['hourly_1', 'hourly_3', 'hourly_6', 'hourly_12', 'daily', 'every_48h', 'weekly'];
        $out['integrity_schedule'] = in_array($schedule, $allowed, true) ? $schedule : $defaults['integrity_schedule'];

        // Apply cron changes after save
        add_action('shutdown', function () {
            self::ensure_cron_state(false);
        });

        return $out;
    }

    public static function render_settings_page(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle actions: baseline or run now
        if (!empty($_POST['ag_action']) && check_admin_referer('ag_actions', 'ag_nonce')) {
            $action = sanitize_text_field((string) $_POST['ag_action']);

            if ($action === 'baseline') {
                $count = self::create_baseline();
                add_settings_error('accolades_guard', 'baseline', 'Baseline created. Files recorded: ' . intval($count), 'updated');
            } elseif ($action === 'run_now') {
                $result = self::run_integrity_check(true);

                // Ensure cards reflect latest schedule/next run immediately after manual check
                self::ensure_cron_state(false);

                if (($result['status'] ?? '') === 'ok') {
                    add_settings_error('accolades_guard', 'run_ok', 'Integrity check complete. No changes detected.', 'updated');
                } else {
                    add_settings_error('accolades_guard', 'run_changed', 'Integrity alert: changes detected and emailed.', 'error');
                }
            }
        }

        settings_errors('accolades_guard');

        $o = self::get_options();

        $baseline = get_option(self::BASELINE_KEY, []);
        $baseline_count = is_array($baseline) ? count($baseline) : 0;

        $next_run_ts = wp_next_scheduled(self::CRON_HOOK);
        $next_run = $next_run_ts ? date_i18n('Y-m-d H:i', $next_run_ts) : 'Not scheduled';

        $schedule_label = self::schedule_label((string) ($o['integrity_schedule'] ?? 'daily'));
        ?>
        <div class="wrap ag-wrap">

            <div class="ag-header">
                <div>
                    <h1>Accolades Guard</h1>
                    <p class="ag-sub">Hardening and integrity monitoring, without bloat.</p>
                </div>

                <div class="ag-actions">
                    <form method="post" class="ag-inline">
                        <?php wp_nonce_field('ag_actions', 'ag_nonce'); ?>
                        <input type="hidden" name="ag_action" value="baseline">
                        <button class="button ag-btn ag-btn-secondary" type="submit">Create Baseline</button>
                    </form>

                    <form method="post" class="ag-inline">
                        <?php wp_nonce_field('ag_actions', 'ag_nonce'); ?>
                        <input type="hidden" name="ag_action" value="run_now">
                        <button id="ag-run-now" class="button ag-btn ag-btn-primary" type="submit">Run Check Now</button>
                    </form>
                </div>
            </div>

            <div class="ag-cards">
                <div class="ag-card">
                    <div class="ag-card-title">Baseline</div>
                    <div class="ag-card-value"><?php echo esc_html((string) $baseline_count); ?> files</div>
                    <div class="ag-card-meta">Recreate after updates</div>
                </div>

                <div class="ag-card">
                    <div class="ag-card-title">Next scheduled check</div>
                    <div class="ag-card-value"><?php echo esc_html($next_run); ?></div>
                    <div class="ag-card-meta"><?php echo esc_html($schedule_label); ?></div>
                </div>

                <div class="ag-card">
                    <div class="ag-card-title">Last run</div>
                    <div class="ag-card-value"><?php echo esc_html($o['integrity_last_run'] ?: 'Never'); ?></div>
                    <div class="ag-card-meta">Stored in plugin options</div>
                </div>
            </div>

            <div class="ag-panel">
                <div class="ag-panel-top">
                    <h2>Controls</h2>
                </div>

                <form method="post" action="options.php" class="ag-form">
                    <?php settings_fields(self::OPTION_KEY); ?>

                    <div class="ag-grid">

                        <div class="ag-section">
                            <h3>Comments and Pingbacks</h3>
                            <?php self::toggle('disable_pingbacks', 'Disable pingbacks and trackbacks', 'Stops internal links showing as comments and blocks pingback abuse.'); ?>
                            <?php self::toggle('block_public_comments', 'Block public comments', 'Prevents comment submissions from being stored in the database.'); ?>
                            <?php self::toggle('allow_admin_comments_only', 'Allow admin comments only', 'Allows only logged-in administrators to comment. Requires "Block public comments".'); ?>
                        </div>

                        <div class="ag-section">
                            <h3>Hardening</h3>
                            <?php self::toggle('block_suspicious_qs', 'Block suspicious query strings', 'Blocks common patterns used in redirect malware and injections.'); ?>
                            <?php self::toggle('disable_file_editors', 'Disable Theme Editor and Plugin Editor', 'Removes editor capabilities, without blocking updates.'); ?>
                        </div>

                        <div class="ag-section">
                            <h3>Developer Signature</h3>
                            <?php self::toggle('frontend_signature', 'Enable frontend HTML comment', 'Adds a comment after the doctype on frontend pages only.'); ?>

                            <div class="ag-row">
                                <label class="ag-label" for="ag_signature">Signature text</label>
                                <input class="ag-input" id="ag_signature" type="text"
                                    name="<?php echo esc_attr(self::OPTION_KEY); ?>[signature_text]"
                                    value="<?php echo esc_attr($o['signature_text']); ?>">
                            </div>
                        </div>

                        <div class="ag-section">
                            <h3>Integrity Monitor</h3>
                            <?php self::toggle('integrity_monitor', 'Enable integrity monitoring', 'Daily integrity scan with email alerts on changes.'); ?>

                            <div class="ag-row">
                                <label class="ag-label" for="ag_scope">Scan scope</label>
                                <select class="ag-select" id="ag_scope" name="<?php echo esc_attr(self::OPTION_KEY); ?>[integrity_scope]">
                                    <option value="core" <?php selected($o['integrity_scope'], 'core'); ?>>WordPress core only</option>
                                    <option value="core_plugins_themes" <?php selected($o['integrity_scope'], 'core_plugins_themes'); ?>>Core + plugins + themes</option>
                                </select>
                            </div>

                            <div class="ag-row">
                                <label class="ag-label" for="ag_email">Alert email</label>
                                <input class="ag-input" id="ag_email" type="email"
                                    name="<?php echo esc_attr(self::OPTION_KEY); ?>[integrity_email]"
                                    value="<?php echo esc_attr($o['integrity_email']); ?>"
                                    placeholder="<?php echo esc_attr(get_option('admin_email')); ?>">
                            </div>

                            <div class="ag-row">
                                <label class="ag-label" for="ag_schedule">Schedule</label>
                                <select class="ag-select" id="ag_schedule" name="<?php echo esc_attr(self::OPTION_KEY); ?>[integrity_schedule]">
                                    <option value="hourly_1" <?php selected($o['integrity_schedule'] ?? 'daily', 'hourly_1'); ?>>Every 1 hour</option>
                                    <option value="hourly_3" <?php selected($o['integrity_schedule'] ?? 'daily', 'hourly_3'); ?>>Every 3 hours</option>
                                    <option value="hourly_6" <?php selected($o['integrity_schedule'] ?? 'daily', 'hourly_6'); ?>>Every 6 hours</option>
                                    <option value="hourly_12" <?php selected($o['integrity_schedule'] ?? 'daily', 'hourly_12'); ?>>Every 12 hours</option>
                                    <option value="daily" <?php selected($o['integrity_schedule'] ?? 'daily', 'daily'); ?>>Every 24 hours (default)</option>
                                    <option value="every_48h" <?php selected($o['integrity_schedule'] ?? 'daily', 'every_48h'); ?>>Every 48 hours</option>
                                    <option value="weekly" <?php selected($o['integrity_schedule'] ?? 'daily', 'weekly'); ?>>Weekly</option>
                                </select>
                                <p class="ag-help">Default is every 24 hours. You can change this anytime.</p>
                            </div>
                        </div>

                    </div>

                    <div class="ag-save">
                        <button type="submit" class="button ag-btn ag-btn-primary ag-btn-lg">Save settings</button>
                    </div>
                </form>
            </div>

        </div>
        <?php
    }

    private static function toggle(string $field, string $title, string $desc): void {
        $o = self::get_options();
        $name = self::OPTION_KEY . '[' . $field . ']';
        ?>
        <div class="ag-toggle">
            <label class="ag-toggle-left">
                <div class="ag-toggle-title"><?php echo esc_html($title); ?></div>
                <div class="ag-toggle-desc"><?php echo esc_html($desc); ?></div>
            </label>
            <label class="ag-switch" data-ag-toggle>
                <input type="checkbox" name="<?php echo esc_attr($name); ?>" value="1" <?php checked(!empty($o[$field])); ?>>
                <span class="ag-slider"></span>
            </label>
        </div>
        <?php
    }

    // Human label for schedule (for the UI cards)
    private static function schedule_label(string $schedule): string {
        switch ($schedule) {
            case 'hourly_1':  return 'Every 1 hour';
            case 'hourly_3':  return 'Every 3 hours';
            case 'hourly_6':  return 'Every 6 hours';
            case 'hourly_12': return 'Every 12 hours';
            case 'every_48h': return 'Every 48 hours';
            case 'weekly':    return 'Weekly';
            case 'daily':
            default:          return 'Every 24 hours (default)';
        }
    }

    // Whether this schedule should start ASAP (instead of tomorrow 03:00)
    private static function schedule_starts_asap(string $schedule): bool {
        return in_array($schedule, ['hourly_1', 'hourly_3', 'hourly_6', 'hourly_12', 'every_48h'], true);
    }

    /* =========================================================
     * Protections
     * ========================================================= */

    public static function filter_xmlrpc_methods(array $methods): array {
        if (!self::enabled('disable_pingbacks')) {
            return $methods;
        }
        unset($methods['pingback.ping']);
        return $methods;
    }

    public static function filter_wp_headers(array $headers): array {
        if (!self::enabled('disable_pingbacks')) {
            return $headers;
        }
        if (isset($headers['X-Pingback'])) {
            unset($headers['X-Pingback']);
        }
        return $headers;
    }

    public static function block_comments_early(): void {
        $opts = self::get_options();

        if (empty($opts['block_public_comments'])) {
            return;
        }

        if (!empty($opts['allow_admin_comments_only'])) {
            if (is_user_logged_in() && current_user_can('administrator')) {
                return;
            }
        }

        status_header(403);
        exit;
    }

    public static function block_suspicious_query_strings(): void {
        if (!self::enabled('block_suspicious_qs')) {
            return;
        }

        $qs = (string) ($_SERVER['QUERY_STRING'] ?? '');
        if ($qs === '') {
            return;
        }

        $bad = [
            'base64_encode',
            'base64_decode',
            'eval(',
            'gzinflate',
            'str_rot13',
            'shell_exec',
            'passthru(',
            'system(',
            'assert(',
            'php://input',
        ];

        foreach ($bad as $needle) {
            if (stripos($qs, $needle) !== false) {
                status_header(403);
                exit;
            }
        }
    }

    public static function restrict_file_edit_caps(array $allcaps, array $caps, array $args, $user): array {
        if (!self::enabled('disable_file_editors')) {
            return $allcaps;
        }

        $allcaps['edit_themes']  = false;
        $allcaps['edit_plugins'] = false;
        $allcaps['edit_files']   = false;

        return $allcaps;
    }

    public static function frontend_signature_buffer(): void {
        if (!self::enabled('frontend_signature')) {
            return;
        }

        if (is_admin() || wp_doing_ajax() || defined('REST_REQUEST')) {
            return;
        }

        $opts = self::get_options();
        $signature = trim((string) ($opts['signature_text'] ?? ''));

        if ($signature === '') {
            return;
        }

        ob_start(function ($buffer) use ($signature) {
            if (stripos($buffer, '<!DOCTYPE html') === false) {
                return $buffer;
            }

            $comment = "\n<!-- " . $signature . " -->\n";
            return preg_replace('/(<!DOCTYPE html[^>]*>)/i', '$1' . $comment, $buffer, 1);
        });
    }

    /* =========================================================
     * Integrity Monitor
     * ========================================================= */

    // Custom cron intervals
    public static function cron_schedules($schedules) {
        $schedules['hourly_1'] = [
            'interval' => HOUR_IN_SECONDS,
            'display'  => 'Every 1 hour',
        ];
        $schedules['hourly_3'] = [
            'interval' => 3 * HOUR_IN_SECONDS,
            'display'  => 'Every 3 hours',
        ];
        $schedules['hourly_6'] = [
            'interval' => 6 * HOUR_IN_SECONDS,
            'display'  => 'Every 6 hours',
        ];
        $schedules['hourly_12'] = [
            'interval' => 12 * HOUR_IN_SECONDS,
            'display'  => 'Every 12 hours',
        ];
        $schedules['every_48h'] = [
            'interval' => 48 * HOUR_IN_SECONDS,
            'display'  => 'Every 48 hours',
        ];
        $schedules['weekly'] = [
            'interval' => 7 * DAY_IN_SECONDS,
            'display'  => 'Weekly',
        ];

        return $schedules;
    }

    private static function map_recurrence(string $schedule): string {
        switch ($schedule) {
            case 'hourly_1':
            case 'hourly_3':
            case 'hourly_6':
            case 'hourly_12':
            case 'every_48h':
            case 'weekly':
            case 'daily':
                return $schedule;
            default:
                return 'daily';
        }
    }

    public static function ensure_cron_state(bool $force = false): void {
        $opts = self::get_options();
        $enabled = !empty($opts['integrity_monitor']);

        if (!$enabled) {
            wp_clear_scheduled_hook(self::CRON_HOOK);
            return;
        }

        $recurrence = self::map_recurrence((string) ($opts['integrity_schedule'] ?? 'daily'));

        $scheduled_ts = wp_next_scheduled(self::CRON_HOOK);
        $current_schedule = $scheduled_ts ? wp_get_schedule(self::CRON_HOOK) : '';

        $needs_reschedule = $force || !$scheduled_ts || ($current_schedule && $current_schedule !== $recurrence);

        if ($needs_reschedule) {
            wp_clear_scheduled_hook(self::CRON_HOOK);

            $now = current_time('timestamp');

            // Start ASAP for hourly-style schedules, keep 03:00 for daily/weekly
            if (self::schedule_starts_asap($recurrence)) {
                $next = $now + 60;
            } else {
                $next = strtotime('tomorrow 03:00', $now);
                if ($next <= $now) {
                    $next = $now + DAY_IN_SECONDS;
                }
            }

            wp_schedule_event($next, $recurrence, self::CRON_HOOK);
        }
    }

    public static function create_baseline(): int {
        $opts = self::get_options();

        $files = self::collect_files($opts['integrity_scope'] ?? 'core');
        $baseline = [];

        foreach ($files as $path) {
            $hash = self::hash_file_safe($path);
            if ($hash) {
                $baseline[$path] = $hash;
            }
        }

        update_option(self::BASELINE_KEY, $baseline, false);
        return count($baseline);
    }

    public static function run_integrity_check(bool $manual = false): array {
        $opts = self::get_options();

        $opts['integrity_last_run'] = gmdate('Y-m-d H:i:s') . ' UTC';
        update_option(self::OPTION_KEY, $opts, false);

        if (empty($opts['integrity_monitor']) && !$manual) {
            return ['status' => 'skipped'];
        }

        $baseline = get_option(self::BASELINE_KEY, null);
        if (!is_array($baseline) || empty($baseline)) {
            self::create_baseline();
            return ['status' => 'ok'];
        }

        $scope = $opts['integrity_scope'] ?? 'core';
        $current_files = self::collect_files($scope);

        $current_map = [];
        foreach ($current_files as $path) {
            $hash = self::hash_file_safe($path);
            if ($hash) {
                $current_map[$path] = $hash;
            }
        }

        $added   = array_diff_key($current_map, $baseline);
        $removed = array_diff_key($baseline, $current_map);

        $changed = [];
        foreach ($current_map as $path => $hash) {
            if (isset($baseline[$path]) && $baseline[$path] !== $hash) {
                $changed[$path] = ['old' => $baseline[$path], 'new' => $hash];
            }
        }

        if (empty($added) && empty($removed) && empty($changed)) {
            return ['status' => 'ok'];
        }

        self::send_integrity_email($added, $removed, $changed, $scope);
        return ['status' => 'changed'];
    }

    private static function send_integrity_email(array $added, array $removed, array $changed, string $scope): void {
        $opts  = self::get_options();
        $to    = $opts['integrity_email'] ? $opts['integrity_email'] : get_option('admin_email');
        $site  = wp_parse_url(home_url(), PHP_URL_HOST);

        $subject = 'Accolades Guard integrity alert on ' . $site;

        $lines = [];
        $lines[] = 'Integrity alert detected changes.';
        $lines[] = 'Site: ' . home_url();
        $lines[] = 'Scope: ' . $scope;
        $lines[] = 'Time: ' . gmdate('Y-m-d H:i:s') . ' UTC';
        $lines[] = '';

        if (!empty($added)) {
            $lines[] = 'ADDED FILES:';
            foreach (array_keys($added) as $path) {
                $lines[] = ' + ' . $path;
            }
            $lines[] = '';
        }

        if (!empty($removed)) {
            $lines[] = 'REMOVED FILES:';
            foreach (array_keys($removed) as $path) {
                $lines[] = ' - ' . $path;
            }
            $lines[] = '';
        }

        if (!empty($changed)) {
            $lines[] = 'CHANGED FILES:';
            foreach ($changed as $path => $pair) {
                $lines[] = ' * ' . $path;
                $lines[] = '   old: ' . $pair['old'];
                $lines[] = '   new: ' . $pair['new'];
            }
            $lines[] = '';
        }

        $lines[] = 'Recommended next steps:';
        $lines[] = '1) If you just updated WP, plugins, or themes, create a new baseline in Accolades Guard.';
        $lines[] = '2) If you did not update anything, investigate these changes immediately.';
        $lines[] = '3) Check for new admin users, unknown plugins, and modified theme files.';

        wp_mail($to, $subject, implode("\n", $lines));
    }

    private static function collect_files(string $scope): array {
        $paths = [];

        $max_bytes = 5 * 1024 * 1024;
        $allowed_ext = ['php', 'js', 'css', 'htm', 'html', 'json', 'txt', 'ini'];

        $add_dir = function (string $dir) use (&$paths, $max_bytes, $allowed_ext) {
            if (!is_dir($dir)) {
                return;
            }

            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                $path = $file->getPathname();

                if (strpos($path, WP_CONTENT_DIR . '/uploads/') !== false) {
                    continue;
                }
                if (strpos($path, WP_CONTENT_DIR . '/cache/') !== false) {
                    continue;
                }

                $size = (int) $file->getSize();
                if ($size <= 0 || $size > $max_bytes) {
                    continue;
                }

                $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                if (!in_array($ext, $allowed_ext, true)) {
                    continue;
                }

                $paths[] = $path;
            }
        };

        $add_dir(ABSPATH . 'wp-admin');
        $add_dir(ABSPATH . WPINC);

        foreach (glob(ABSPATH . '*.php') ?: [] as $root_php) {
            $size = @filesize($root_php);
            if (is_file($root_php) && $size > 0 && $size <= $max_bytes) {
                $paths[] = $root_php;
            }
        }

        if ($scope === 'core_plugins_themes') {
            $add_dir(WP_PLUGIN_DIR);
            $add_dir(get_theme_root());
        }

        $paths = array_values(array_unique($paths));
        sort($paths);

        return $paths;
    }

    private static function hash_file_safe(string $path): string {
        if (!is_readable($path)) {
            return '';
        }
        $hash = @hash_file('sha256', $path);
        return is_string($hash) ? $hash : '';
    }
}

Accolades_Guard::init();

register_activation_hook(__FILE__, ['Accolades_Guard', 'activate']);
register_deactivation_hook(__FILE__, ['Accolades_Guard', 'deactivate']);

/**
 * Plugins page: Settings link next to Deactivate
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    $links = is_array($links) ? $links : [];
    $settings_link = '<a href="' . esc_url(admin_url('admin.php?page=accolades-guard')) . '">Settings</a>';
    array_unshift($links, $settings_link);
    return $links;
});

/**
 * Plugins page: Support / Donate / GitHub links under description
 */
add_filter('plugin_row_meta', function ($links, $file) {
    if ($file !== plugin_basename(__FILE__)) {
        return $links;
    }

    $links[] = '<a href="mailto:accolades.dev@gmail.com">Support</a>';
    $links[] = '<a href="https://donate.stripe.com/bJeeVf50m3Spezm6vn8AE03" target="_blank" rel="noopener noreferrer">Donate</a>';
    $links[] = '<a href="https://github.com/luc-constantin" target="_blank" rel="noopener noreferrer">GitHub</a>';

    return $links;
}, 10, 2);