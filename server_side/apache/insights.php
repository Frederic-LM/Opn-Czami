<?php
/**
 * ============================================================================
 * Op'n-Czami Insights Handler (insights.php)
 *
 * Purpose:
 *   - Logs certificate view events (QR scans) to analytics.log
 *   - Performs monthly log rotation to archive old analytics data
 *   - Serves the requested .lky certificate file to the client
 *   - Thread-safe file operations using advisory locking
 *
 * Behavior is controlled by: .analytics-config.json
 * - If "logging_enabled": true → logs to analytics.log
 * - If "logging_enabled": false → serves files without logging (privacy mode)
 *
 * Filters:
 *   - Skips logging of test/debug requests (opnczami_*, __opnczami_*, file_that*)
 *   - Only logs legitimate .lky certificate downloads
 *
 * Requirements:
 *   - PHP 7.0 or higher
 *   - Apache with mod_rewrite enabled
 *   - Write permissions for the directory (755 recommended)
 *   - flock(), rename(), file_put_contents() must be enabled (no open_basedir restrictions)
 *
 * License: MIT (See LICENSE file)
 * ============================================================================
 */

// ============================================================================
// Configuration Loading
// ============================================================================

/**
 * Load analytics configuration
 *
 * Configuration file: .analytics-config.json
 * Default: logging_enabled = true (for backward compatibility)
 */
function load_analytics_config() {
    $config_file = '.analytics-config.json';
    $default_config = array('logging_enabled' => true);

    if (!file_exists($config_file)) {
        return $default_config;
    }

    $content = @file_get_contents($config_file);
    if (!$content) {
        return $default_config;
    }

    $config = json_decode($content, true);
    if (!is_array($config)) {
        return $default_config;
    }

    return $config;
}

// Load configuration once at startup
$analytics_config = load_analytics_config();
$logging_enabled = isset($analytics_config['logging_enabled']) ? (bool) $analytics_config['logging_enabled'] : true;

// ============================================================================
// Monthly Log Rotation
// ============================================================================

/**
 * Rotates the analytics log monthly to archive old data
 *
 * Files created:
 * - analytics.log         (current month's log)
 * - analytics-2025-10.log (previous month's archive)
 *
 * Uses advisory file locking to prevent concurrent rotation issues
 */
function rotate_analytics_log_if_needed() {
    $current_month = date('Y-m');  // e.g., "2025-10"
    $lock_file = '.insights-rotation.lock';
    $metadata_file = '.insights-metadata.json';

    // Read metadata to check last rotation month
    $metadata = array();
    if (file_exists($metadata_file)) {
        $content = @file_get_contents($metadata_file);
        if ($content) {
            $metadata = json_decode($content, true) ?: array();
        }
    }

    $last_rotation_month = isset($metadata['last_rotation_month']) ? $metadata['last_rotation_month'] : null;

    // Check if rotation needed
    if ($last_rotation_month !== $current_month) {
        // Try to acquire lock (non-blocking)
        $lock_handle = @fopen($lock_file, 'c');
        if ($lock_handle && flock($lock_handle, LOCK_EX | LOCK_NB)) {
            try {
                // Double-check inside lock (another process might have rotated)
                $metadata = array();
                if (file_exists($metadata_file)) {
                    $content = @file_get_contents($metadata_file);
                    if ($content) {
                        $metadata = json_decode($content, true) ?: array();
                    }
                }
                $last_rotation_month = isset($metadata['last_rotation_month']) ? $metadata['last_rotation_month'] : null;

                // If still different month, perform rotation
                if ($last_rotation_month !== $current_month) {
                    // Archive old log (if it exists and has content)
                    if (file_exists('insights.log') && filesize('insights.log') > 0) {
                        $prev_month = date('Y-m', strtotime('first day of last month'));
                        $archive_log = 'insights-' . $prev_month . '.log';
                        @rename('insights.log', $archive_log);
                    }

                    // Create new empty log
                    @touch('insights.log');

                    // Update metadata
                    $metadata['last_rotation_month'] = $current_month;
                    $metadata['last_rotation_time'] = date('Y-m-d H:i:s');
                    @file_put_contents($metadata_file, json_encode($metadata));
                }
            } finally {
                flock($lock_handle, LOCK_UN);
                fclose($lock_handle);
            }
        }
    }
}

/**
 * ============================================================================
 * Event Logging
 * ============================================================================
 */

/**
 * Appends an event to the analytics log (thread-safe)
 *
 * Log format:
 * YYYY-MM-DD HH:MM:SS | IP_ADDRESS | certificate_filename
 *
 * Example:
 * 2025-10-25 14:32:15 | 192.168.1.100 | certificate_abc123def456
 *
 * @param string $ip The visitor's IP address (from REMOTE_ADDR or X-Forwarded-For)
 * @param string $filename The certificate filename being accessed
 * @return bool True if successfully logged, false otherwise
 */
function append_analytics_event($ip, $filename) {
    // Sanitize inputs
    $ip = trim($ip);
    $filename = trim($filename);

    // Basic validation
    if (empty($ip) || empty($filename)) {
        return false;
    }

    // Build event line: TIMESTAMP | IP | FILENAME
    $timestamp = date('Y-m-d H:i:s');
    $event = $timestamp . ' | ' . $ip . ' | ' . $filename . "\n";

    // Append with file locking (retry up to 3 times if lock is busy)
    $retries = 3;
    for ($i = 0; $i < $retries; $i++) {
        $handle = @fopen('insights.log', 'a');
        if ($handle) {
            if (flock($handle, LOCK_EX)) {
                fwrite($handle, $event);
                flock($handle, LOCK_UN);
                fclose($handle);
                return true;
            }
            fclose($handle);
        }
        if ($i < $retries - 1) {
            usleep(50000);  // 50ms delay before retry
        }
    }

    return false;
}

/**
 * ============================================================================
 * Main Handler
 * ============================================================================
 */

// Perform log rotation check only if logging is enabled
if ($logging_enabled) {
    rotate_analytics_log_if_needed();
}

// Get the requested filename from the URL query parameter
// The .htaccess file rewrites /certificate123 to ?file=certificate123
$file = basename($_GET['file'] ?? '');
if (empty($file)) {
    http_response_code(400);
    exit('Bad request: missing file parameter');
}

// Skip logging for test/debug requests (these should not appear in analytics)
// These patterns indicate compatibility checks, keystore tests, or internal checks
$skip_patterns = [
    'opnczami_',     // Compatibility check: opnczami_compat_check_*
    '__opnczami_',   // Internal test: __opnczami_check
    'file_that'      // Invalid file: file_that_does_not_exist
];

$is_test_request = false;
foreach ($skip_patterns as $pattern) {
    if (strpos($file, $pattern) === 0) {
        $is_test_request = true;
        break;
    }
}

/**
 * Extract IP address (handles proxies)
 *
 * Checks X-Forwarded-For header first (for proxied requests)
 * Falls back to REMOTE_ADDR for direct connections
 * If multiple IPs in X-Forwarded-For, takes the first one (client's real IP)
 */
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (strpos($ip, ',') !== false) {
    $ip = explode(',', $ip)[0];  // Take first IP if multiple
}
$ip = trim($ip);

// Record the event only if:
// 1. Logging is enabled
// 2. This is NOT a test/debug request
// (but don't fail if logging fails)
if ($logging_enabled && !$is_test_request) {
    append_analytics_event($ip, $file);
}

/**
 * Serve the .lky certificate file
 *
 * The .lky file must exist in the same directory as this script
 * Format: {filename}.lky
 */
$filepath = $file . '.lky';
if (!file_exists($filepath)) {
    http_response_code(404);
    exit('File not found: ' . htmlspecialchars($file));
}

// Serve the file with appropriate headers
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
header('Content-Length: ' . filesize($filepath));

readfile($filepath);
?>
