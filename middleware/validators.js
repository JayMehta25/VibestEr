/**
 * Input Validation Middleware
 * Schema-based validation using Joi for all user inputs
 * Prevents injection attacks and ensures data integrity
 */

import Joi from 'joi';
import {
    USERNAME_RULES,
    PASSWORD_RULES,
    EMAIL_RULES,
    OTP_RULES,
    ROOM_CODE_RULES,
    MESSAGE_RULES,
    INTEREST_RULES,
} from '../config/security-config.js';

// ==========================================
// VALIDATION SCHEMAS
// ==========================================

/**
 * User registration schema
 * Validates username, email, and password
 */
export const registerSchema = Joi.object({
    username: Joi.string()
        .min(USERNAME_RULES.minLength)
        .max(USERNAME_RULES.maxLength)
        .pattern(USERNAME_RULES.pattern)
        .required()
        .messages({
            'string.pattern.base': USERNAME_RULES.errorMessage,
            'string.min': `Username must be at least ${USERNAME_RULES.minLength} characters`,
            'string.max': `Username cannot exceed ${USERNAME_RULES.maxLength} characters`,
            'any.required': 'Username is required',
        }),
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': EMAIL_RULES.errorMessage,
            'any.required': 'Email is required',
        }),
    password: Joi.string()
        .min(PASSWORD_RULES.minLength)
        .max(PASSWORD_RULES.maxLength)
        .required()
        .messages({
            'string.min': PASSWORD_RULES.errorMessage,
            'string.max': `Password cannot exceed ${PASSWORD_RULES.maxLength} characters`,
            'any.required': 'Password is required',
        }),
}).options({ stripUnknown: true }); // Remove any unexpected fields

/**
 * User login schema
 * Validates email and password
 */
export const loginSchema = Joi.object({
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': EMAIL_RULES.errorMessage,
            'any.required': 'Email is required',
        }),
    password: Joi.string()
        .required()
        .messages({
            'any.required': 'Password is required',
        }),
}).options({ stripUnknown: true });

/**
 * OTP verification schema
 * Validates email and 6-digit OTP
 */
export const verifyOtpSchema = Joi.object({
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': EMAIL_RULES.errorMessage,
            'any.required': 'Email is required',
        }),
    otp: Joi.string()
        .pattern(OTP_RULES.pattern)
        .required()
        .messages({
            'string.pattern.base': OTP_RULES.errorMessage,
            'any.required': 'OTP is required',
        }),
}).options({ stripUnknown: true });

/**
 * Send verification OTP schema
 * Validates email only
 */
export const sendOtpSchema = Joi.object({
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': EMAIL_RULES.errorMessage,
            'any.required': 'Email is required',
        }),
}).options({ stripUnknown: true });

/**
 * Forgot password schema
 * Validates email only
 */
export const forgotPasswordSchema = Joi.object({
    email: Joi.string()
        .email()
        .required()
        .messages({
            'string.email': EMAIL_RULES.errorMessage,
            'any.required': 'Email is required',
        }),
}).options({ stripUnknown: true });

/**
 * Reset password schema
 * Validates new password
 */
export const resetPasswordSchema = Joi.object({
    password: Joi.string()
        .min(PASSWORD_RULES.minLength)
        .max(PASSWORD_RULES.maxLength)
        .required()
        .messages({
            'string.min': PASSWORD_RULES.errorMessage,
            'string.max': `Password cannot exceed ${PASSWORD_RULES.maxLength} characters`,
            'any.required': 'Password is required',
        }),
}).options({ stripUnknown: true });

/**
 * Room code schema
 * Validates 6-character alphanumeric room code
 */
export const roomCodeSchema = Joi.object({
    roomCode: Joi.string()
        .length(ROOM_CODE_RULES.length)
        .pattern(ROOM_CODE_RULES.pattern)
        .required()
        .messages({
            'string.pattern.base': ROOM_CODE_RULES.errorMessage,
            'string.length': ROOM_CODE_RULES.errorMessage,
            'any.required': 'Room code is required',
        }),
    username: Joi.string()
        .min(USERNAME_RULES.minLength)
        .max(USERNAME_RULES.maxLength)
        .required()
        .messages({
            'any.required': 'Username is required',
        }),
}).options({ stripUnknown: true });

/**
 * Message content schema
 * Validates message text with length limits
 */
export const messageSchema = Joi.object({
    text: Joi.string()
        .max(MESSAGE_RULES.maxLength)
        .allow('')
        .messages({
            'string.max': MESSAGE_RULES.errorMessage,
        }),
    roomCode: Joi.string().required(),
    username: Joi.string().required(),
    // Allow other fields like attachments, timestamp, etc.
}).options({ allowUnknown: true });

/**
 * Interests array schema
 * Validates array of interests with count and content limits
 */
export const interestsSchema = Joi.object({
    interests: Joi.array()
        .items(
            Joi.string()
                .min(INTEREST_RULES.minLength)
                .max(INTEREST_RULES.maxLength)
                .pattern(INTEREST_RULES.pattern)
                .messages({
                    'string.pattern.base': INTEREST_RULES.errorMessage,
                    'string.min': `Interest must be at least ${INTEREST_RULES.minLength} characters`,
                    'string.max': `Interest cannot exceed ${INTEREST_RULES.maxLength} characters`,
                })
        )
        .max(INTEREST_RULES.maxCount)
        .required()
        .messages({
            'array.max': `Cannot have more than ${INTEREST_RULES.maxCount} interests`,
            'any.required': 'Interests are required',
        }),
}).options({ allowUnknown: true });

/**
 * AI prompt schema
 * Validates AI prompts with reasonable length limits
 */
export const aiPromptSchema = Joi.object({
    prompt: Joi.string()
        .max(2000)
        .required()
        .messages({
            'string.max': 'Prompt cannot exceed 2000 characters',
            'any.required': 'Prompt is required',
        }),
}).options({ allowUnknown: true });

/**
 * AI icebreaker schema
 * Validates interests array for icebreaker generation
 */
export const icebreakerSchema = Joi.object({
    interests: Joi.array()
        .items(Joi.string().max(50))
        .max(10)
        .default([])
        .messages({
            'array.max': 'Cannot have more than 10 interests',
        }),
}).options({ stripUnknown: true });

// ==========================================
// VALIDATION MIDDLEWARE FACTORY
// ==========================================

/**
 * Creates validation middleware for a given schema
 * @param {Joi.Schema} schema - Joi validation schema
 * @param {string} source - Where to validate from ('body', 'params', 'query')
 * @returns {Function} Express middleware function
 */
export function validate(schema, source = 'body') {
    return (req, res, next) => {
        const dataToValidate = req[source];

        const { error, value } = schema.validate(dataToValidate, {
            abortEarly: false, // Return all errors, not just the first one
            stripUnknown: true, // Remove unknown fields
        });

        if (error) {
            // Extract error messages
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message,
            }));

            console.log(`❌ Validation failed for ${req.method} ${req.path}:`, errors);

            return res.status(400).json({
                message: 'Validation failed',
                errors: errors,
            });
        }

        // Replace request data with validated and sanitized data
        req[source] = value;
        next();
    };
}

// ==========================================
// SANITIZATION MIDDLEWARE
// ==========================================

/**
 * Sanitize user input to prevent XSS attacks
 * This middleware should be applied after validation
 */
export function sanitizeInput(req, res, next) {
    // The xss-clean package will handle this automatically
    // This is just a placeholder for any custom sanitization logic
    next();
}

// ==========================================
// EXPORT VALIDATION MIDDLEWARE
// ==========================================

/**
 * Pre-configured validation middleware for common endpoints
 */
export const validators = {
    register: validate(registerSchema),
    login: validate(loginSchema),
    verifyOtp: validate(verifyOtpSchema),
    sendOtp: validate(sendOtpSchema),
    forgotPassword: validate(forgotPasswordSchema),
    resetPassword: validate(resetPasswordSchema),
    roomCode: validate(roomCodeSchema),
    message: validate(messageSchema),
    interests: validate(interestsSchema),
    aiPrompt: validate(aiPromptSchema),
    icebreaker: validate(icebreakerSchema),
};
