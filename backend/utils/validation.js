/**
 * Shared input validation helpers.
 * Keeping these centralized avoids inconsistent checks across routes.
 */

function isValidUrl(value) {
  if (!value || typeof value !== 'string') return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function isValidEmail(value) {
  if (!value || typeof value !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function isNonEmptyString(value, maxLen = 20000) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maxLen;
}

function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, 20000);
}

const ALLOWED_FILE_EXTENSIONS = [
  '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.zip', '.csv', '.log'
];

function isAllowedFileType(filename) {
  if (!filename) return false;
  const lower = filename.toLowerCase();
  return ALLOWED_FILE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

module.exports = {
  isValidUrl,
  isValidEmail,
  isNonEmptyString,
  sanitizeText,
  isAllowedFileType,
  ALLOWED_FILE_EXTENSIONS
};
