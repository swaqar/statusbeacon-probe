import crypto from 'crypto';

/**
 * Content Validation Library - Phase 2.2
 *
 * Validates HTTP response content to detect:
 * - Wrong content (maintenance pages, errors)
 * - Defacement attacks
 * - Breaking API changes
 * - Missing required elements
 */

export interface ContentValidationConfig {
  enabled: boolean;
  type: 'keyword' | 'regex' | 'hash' | 'json' | 'size';

  // Keyword validation
  mustContain?: string[];
  mustNotContain?: string[];
  caseSensitive?: boolean;

  // Regex validation
  pattern?: string;
  shouldMatch?: boolean;

  // Hash validation
  expectedHash?: string;
  algorithm?: 'sha256' | 'md5' | 'sha1';
  detectChanges?: boolean; // Alert on any hash change

  // JSON validation
  jsonSchema?: Record<string, any>;
  requiredFields?: string[];

  // Size validation
  minBytes?: number;
  maxBytes?: number;
}

export interface ValidationResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  contentHash?: string;
  responseSize?: number;
}

/**
 * Validate content based on configuration
 */
export async function validateContent(
  content: string,
  config: ContentValidationConfig
): Promise<ValidationResult> {
  if (!config.enabled) {
    return { passed: true, errors: [], warnings: [] };
  }

  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
    responseSize: Buffer.byteLength(content, 'utf8'),
  };

  try {
    switch (config.type) {
      case 'keyword':
        return validateKeywords(content, config);

      case 'regex':
        return validateRegex(content, config);

      case 'hash':
        return validateHash(content, config);

      case 'json':
        return validateJSON(content, config);

      case 'size':
        return validateSize(content, config);

      default:
        result.errors.push(`Unknown validation type: ${config.type}`);
        result.passed = false;
    }
  } catch (error) {
    result.errors.push(`Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    result.passed = false;
  }

  return result;
}

/**
 * Keyword Validation
 * Check if content contains or doesn't contain specific keywords
 */
function validateKeywords(content: string, config: ContentValidationConfig): ValidationResult {
  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
    responseSize: Buffer.byteLength(content, 'utf8'),
  };

  const searchContent = config.caseSensitive ? content : content.toLowerCase();

  // Check required keywords
  if (config.mustContain && config.mustContain.length > 0) {
    for (const keyword of config.mustContain) {
      const searchKeyword = config.caseSensitive ? keyword : keyword.toLowerCase();
      if (!searchContent.includes(searchKeyword)) {
        result.errors.push(`Required keyword not found: "${keyword}"`);
        result.passed = false;
      }
    }
  }

  // Check forbidden keywords
  if (config.mustNotContain && config.mustNotContain.length > 0) {
    for (const keyword of config.mustNotContain) {
      const searchKeyword = config.caseSensitive ? keyword : keyword.toLowerCase();
      if (searchContent.includes(searchKeyword)) {
        result.errors.push(`Forbidden keyword found: "${keyword}"`);
        result.passed = false;
      }
    }
  }

  return result;
}

/**
 * Regex Validation
 * Check if content matches a specific pattern
 */
function validateRegex(content: string, config: ContentValidationConfig): ValidationResult {
  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
    responseSize: Buffer.byteLength(content, 'utf8'),
  };

  if (!config.pattern) {
    result.errors.push('Regex pattern not specified');
    result.passed = false;
    return result;
  }

  try {
    const regex = new RegExp(config.pattern);
    const matches = regex.test(content);

    if (config.shouldMatch && !matches) {
      result.errors.push(`Content does not match pattern: ${config.pattern}`);
      result.passed = false;
    } else if (!config.shouldMatch && matches) {
      result.errors.push(`Content matches forbidden pattern: ${config.pattern}`);
      result.passed = false;
    }
  } catch (error) {
    result.errors.push(`Invalid regex pattern: ${error instanceof Error ? error.message : 'Unknown error'}`);
    result.passed = false;
  }

  return result;
}

/**
 * Hash Validation
 * Detect content changes or verify against expected hash
 */
function validateHash(content: string, config: ContentValidationConfig): ValidationResult {
  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
    responseSize: Buffer.byteLength(content, 'utf8'),
  };

  const algorithm = config.algorithm || 'sha256';
  const hash = crypto.createHash(algorithm).update(content).digest('hex');
  result.contentHash = hash;

  if (config.expectedHash) {
    if (hash !== config.expectedHash) {
      if (config.detectChanges) {
        result.warnings.push(`Content changed - hash mismatch (expected: ${config.expectedHash.substring(0, 12)}..., got: ${hash.substring(0, 12)}...)`);
        // Not an error if we're just detecting changes
      } else {
        result.errors.push(`Content hash mismatch (expected: ${config.expectedHash.substring(0, 12)}..., got: ${hash.substring(0, 12)}...)`);
        result.passed = false;
      }
    }
  }

  return result;
}

/**
 * JSON Validation
 * Validate API response structure and required fields
 */
function validateJSON(content: string, config: ContentValidationConfig): ValidationResult {
  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
    responseSize: Buffer.byteLength(content, 'utf8'),
  };

  // Try to parse JSON
  let json: any;
  try {
    json = JSON.parse(content);
  } catch (error) {
    result.errors.push(`Invalid JSON: ${error instanceof Error ? error.message : 'Parse error'}`);
    result.passed = false;
    return result;
  }

  // Check required fields
  if (config.requiredFields && config.requiredFields.length > 0) {
    for (const field of config.requiredFields) {
      const fieldPath = field.split('.');
      let value = json;

      for (const key of fieldPath) {
        if (value && typeof value === 'object' && key in value) {
          value = value[key];
        } else {
          result.errors.push(`Required field missing: ${field}`);
          result.passed = false;
          break;
        }
      }
    }
  }

  // Validate against schema (basic validation)
  if (config.jsonSchema) {
    const schemaErrors = validateJSONSchema(json, config.jsonSchema);
    if (schemaErrors.length > 0) {
      result.errors.push(...schemaErrors);
      result.passed = false;
    }
  }

  return result;
}

/**
 * Basic JSON schema validation
 */
function validateJSONSchema(json: any, schema: Record<string, any>): string[] {
  const errors: string[] = [];

  for (const [key, expectedType] of Object.entries(schema)) {
    if (!(key in json)) {
      errors.push(`Schema validation: Missing key "${key}"`);
      continue;
    }

    const actualType = Array.isArray(json[key]) ? 'array' : typeof json[key];

    if (typeof expectedType === 'string') {
      if (actualType !== expectedType) {
        errors.push(`Schema validation: "${key}" should be ${expectedType}, got ${actualType}`);
      }
    } else if (typeof expectedType === 'object' && !Array.isArray(expectedType)) {
      // Nested object validation
      if (actualType === 'object') {
        const nestedErrors = validateJSONSchema(json[key], expectedType);
        errors.push(...nestedErrors.map(e => `${key}.${e}`));
      } else {
        errors.push(`Schema validation: "${key}" should be object, got ${actualType}`);
      }
    }
  }

  return errors;
}

/**
 * Size Validation
 * Validate response size is within expected range
 */
function validateSize(content: string, config: ContentValidationConfig): ValidationResult {
  const result: ValidationResult = {
    passed: true,
    errors: [],
    warnings: [],
  };

  const size = Buffer.byteLength(content, 'utf8');
  result.responseSize = size;

  if (config.minBytes !== undefined && size < config.minBytes) {
    result.errors.push(`Response too small: ${size} bytes (expected at least ${config.minBytes} bytes)`);
    result.passed = false;
  }

  if (config.maxBytes !== undefined && size > config.maxBytes) {
    result.errors.push(`Response too large: ${size} bytes (expected at most ${config.maxBytes} bytes)`);
    result.passed = false;
  }

  return result;
}

/**
 * Generate content hash for change detection
 */
export function generateContentHash(content: string, algorithm: 'sha256' | 'md5' | 'sha1' = 'sha256'): string {
  return crypto.createHash(algorithm).update(content).digest('hex');
}

/**
 * Helper: Extract meaningful content for validation
 * Removes whitespace variations to avoid false positives from formatting changes
 */
export function normalizeContent(content: string): string {
  return content
    .replace(/\s+/g, ' ')  // Normalize whitespace
    .trim();
}
