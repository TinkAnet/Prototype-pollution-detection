// config.js

// Import configurations from other files
import {
    RATE_LIMITS,
    AVAILABLE_MODELS,
    MODEL_INFO,
  } from './model-config.js';
  
  import {
    MOA_CONFIG as initialMoaConfig,
    getLayerConfig,
    getMainModelConfig,
  } from './moa-config.js';
  
  import {
    API_CONFIG,
    SYSTEM_SETTINGS,
    ENVIRONMENT,
    isProduction,
    getApiKey,
  } from './system-config.js';

  import { createMOADiagram, updateMOADiagram } from '../diagram/diagram.js';
  
  // Export configurations
  export const rateLimits = RATE_LIMITS;
  export const availableModels = AVAILABLE_MODELS;
  export const modelInfo = MODEL_INFO;
  export const systemSettings = SYSTEM_SETTINGS;
  export const environment = ENVIRONMENT;
  export { getLayerConfig, getMainModelConfig, isProduction };
  
  // Export API configuration
  export const API_ENDPOINT = API_CONFIG.ENDPOINT;
  export const API_KEY = getApiKey();
  
  // Initialize moaConfig with default values
  export let moaConfig = {
    ...initialMoaConfig,
    connections: initialMoaConfig.connections || [],
    error_handling: {
        graceful_degradation: {
            enabled: true,
            fallback_chain: ['hermes3', 'llama3-8b-8192', 'gemma-7b-it', 'llama3-70b-8192'],
            fallback_model: 'hermes3'
        },
        max_retries: 3,
        retry_delay: 1000
    },
    self_evolving: {
        enabled: true,
        learning_rate: 0.01,
        feedback_threshold: 0.7,
        improvement_interval: 24 * 60 * 60 * 1000 // 24 hours
    },
    function_calling: {
        enabled: false,
        model: 'llama3-groq-70b-8192-tool-use-preview'
    }
  };
  
  /**
   * Updates the MOA configuration with new settings.
   * 
   * How it works:
   * 1. Validates the new configuration
   * 2. Deep merges the new config with the existing one
   * 3. Updates rate limits if the main model has changed
   * 4. Recalculates adaptive thresholds if needed
   * 5. Updates visualization settings if needed
   * 6. Updates MOA controls in the UI
   * 7. Updates the MOA diagram
   * 8. Dispatches a custom event to notify other parts of the application
   * 
   * Usage example:
   * ```javascript
   * updateMOAConfig({
   *   main_model: 'llama3-70b-8192',
   *   adaptive_threshold: {
   *     processing_time: 5000,
   *     output_quality: 0.8
   *   }
   * });
   * ```
   * 
   * Files that use this function:
   * - js/main/app-initializer.js
   * - js/ui/config-panel.js
   * - js/services/moa-service.js
   * 
   * Role in overall program logic:
   * This function is crucial for dynamically updating the MOA system's configuration.
   * It ensures that all parts of the application are synchronized with the latest settings,
   * including the UI, visualization, and core MOA logic.
   * 
   * [Documentation](./docs/config.md#updateMOAConfig)
   * 
   * @param {Object} newConfig - The new configuration object to be merged with the existing one.
   * @throws {Error} If the new configuration is invalid.
   */
  export function updateMOAConfig(newConfig = {}) {
    if (!isValidConfig(newConfig)) {
      throw new Error('Invalid MOA configuration');
    }
  
    // Deep merge newConfig into moaConfig
    moaConfig = deepMerge(moaConfig, newConfig);
  
    // Update rate limit if main_model has changed
    if (moaConfig.main_model && rateLimits[moaConfig.main_model]) {
      moaConfig.rate_limit = rateLimits[moaConfig.main_model];
    }
  
    // Recalculate adaptive thresholds if needed
    if (newConfig.adaptive_threshold) {
      recalculateAdaptiveThresholds();
    }
  
    // Update visualization settings if needed
    if (newConfig.visualization) {
      updateVisualizationSettings();
    }
  
    // Update MOA controls in the UI
    updateMOAControls();
  
    // Update the MOA diagram
    updateMOADiagram();
  
    // Dispatch an event to notify other parts of the application
    const event = new CustomEvent('moaConfigUpdated', { detail: moaConfig });
    window.dispatchEvent(event);
  
    console.log('MOA configuration updated:', moaConfig);
  }
  
  // Helper functions
  /**
   * Performs a deep merge of two objects.
   * 
   * How it works:
   * 1. Checks if both target and source are objects
   * 2. If they are, it recursively merges their properties
   * 3. If not, it returns the source value
   * 
   * Usage example:
   * ```javascript
   * const target = { a: { b: 1 }, c: 2 };
   * const source = { a: { d: 3 }, e: 4 };
   * const result = deepMerge(target, source);
   * // result: { a: { b: 1, d: 3 }, c: 2, e: 4 }
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in updateMOAConfig)
   * 
   * Role in overall program logic:
   * This function is essential for updating the MOA configuration while preserving
   * existing settings that are not explicitly overwritten.
   * 
   * [Documentation](./docs/config.md#deepMerge)
   * 
   * @param {Object} target - The target object to merge into.
   * @param {Object} source - The source object to merge from.
   * @returns {Object} The merged object.
   */
  function deepMerge(target, source) {
    if (isObject(target) && isObject(source)) {
      const output = { ...target };
      for (const key of Object.keys(source)) {
        if (isObject(source[key])) {
          output[key] = key in target ? deepMerge(target[key], source[key]) : source[key];
        } else if (Array.isArray(source[key])) {
          output[key] = [...source[key]];
        } else {
          output[key] = source[key];
        }
      }
      return output;
    }
    return source;
  }
  
  /**
   * Checks if the given item is an object (excluding arrays).
   * 
   * How it works:
   * 1. Checks if the item is truthy
   * 2. Checks if the item is of type 'object'
   * 3. Ensures the item is not an array
   * 
   * Usage example:
   * ```javascript
   * console.log(isObject({})); // true
   * console.log(isObject([])); // false
   * console.log(isObject(null)); // false
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in deepMerge)
   * 
   * Role in overall program logic:
   * This function supports the deep merge operation by distinguishing
   * between plain objects and other types of values.
   * 
   * [Documentation](./docs/config.md#isObject)
   * 
   * @param {*} item - The item to check.
   * @returns {boolean} True if the item is an object (not an array), false otherwise.
   */
  function isObject(item) {
    return item && typeof item === 'object' && !Array.isArray(item);
  }
  
  /**
   * Validates the MOA configuration object.
   * 
   * How it works:
   * 1. Checks the validity of the main_model
   * 2. Validates the structure and content of layers
   * 3. Verifies self_evolving settings
   * 4. Checks function_calling settings
   * 
   * Usage example:
   * ```javascript
   * const newConfig = {
   *   main_model: 'llama3-70b-8192',
   *   layers: [[{ model_name: 'gemma-7b-it', temperature: 0.7 }]],
   *   self_evolving: { learning_rate: 0.01, feedback_threshold: 0.7, improvement_interval: 86400000 },
   *   function_calling: { enabled: true, model: 'llama3-groq-70b-8192-tool-use-preview' }
   * };
   * console.log(isValidConfig(newConfig)); // true
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in updateMOAConfig)
   * 
   * Role in overall program logic:
   * This function ensures that only valid configurations are applied to the MOA system,
   * preventing potential errors and maintaining system integrity.
   * 
   * [Documentation](./docs/config.md#isValidConfig)
   * 
   * @param {Object} config - The configuration object to validate.
   * @returns {boolean} True if the configuration is valid, false otherwise.
   */
  function isValidConfig(config) {
    // Validate main_model
    if (config.main_model && !availableModels.includes(config.main_model)) {
      console.error(`Invalid main_model: ${config.main_model}`);
      return false;
    }
  
    // Validate layers
    if (config.layers) {
      if (!Array.isArray(config.layers)) {
        console.error('layers should be an array');
        return false;
      }
      for (const layer of config.layers) {
        if (!Array.isArray(layer)) {
          console.error('Each layer should be an array');
          return false;
        }
        for (const agent of layer) {
          if (!availableModels.includes(agent.model_name)) {
            console.error(`Invalid agent model_name: ${agent.model_name}`);
            return false;
          }
          if (typeof agent.temperature !== 'number' || agent.temperature < 0 || agent.temperature > 1) {
            console.error(`Invalid agent temperature: ${agent.temperature}`);
            return false;
          }
        }
      }
    }
  
    // Validate self_evolving settings
    if (config.self_evolving) {
      const { learning_rate, feedback_threshold, improvement_interval } = config.self_evolving;
      if (typeof learning_rate !== 'number' || learning_rate <= 0 || learning_rate > 1) {
        console.error(`Invalid learning_rate: ${learning_rate}`);
        return false;
      }
      if (typeof feedback_threshold !== 'number' || feedback_threshold < 0 || feedback_threshold > 1) {
        console.error(`Invalid feedback_threshold: ${feedback_threshold}`);
        return false;
      }
      if (typeof improvement_interval !== 'number' || improvement_interval < 0) {
        console.error(`Invalid improvement_interval: ${improvement_interval}`);
        return false;
      }
    }
  
    // Validate function_calling settings
    if (config.function_calling) {
      const { enabled, model } = config.function_calling;
      if (typeof enabled !== 'boolean') {
        console.error(`Invalid function_calling enabled: ${enabled}`);
        return false;
      }
      if (model && !availableModels.includes(model)) {
        console.error(`Invalid function_calling model: ${model}`);
        return false;
      }
    }
  
    return true;
  }
  
  /**
   * Recalculates adaptive thresholds based on the current MOA configuration.
   * 
   * How it works:
   * 1. Retrieves current adaptive threshold values
   * 2. Adjusts processing time based on the number of layers
   * 3. Increases output quality slightly, capping at 1.0
   * 4. Updates the moaConfig with new threshold values
   * 
   * Usage example:
   * ```javascript
   * // After updating layers or other relevant settings
   * recalculateAdaptiveThresholds();
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in updateMOAConfig)
   * 
   * Role in overall program logic:
   * This function ensures that the adaptive thresholds remain appropriate
   * as the MOA configuration changes, maintaining optimal performance.
   * 
   * [Documentation](./docs/config.md#recalculateAdaptiveThresholds)
   */
  function recalculateAdaptiveThresholds() {
    // Implement logic to recalculate adaptive thresholds
    const { processing_time, output_quality } = moaConfig.adaptive_threshold;
  
    // Example adjustments
    const newProcessingTime = processing_time * (moaConfig.layers.length / 2);
    const newOutputQuality = Math.min(output_quality * 1.1, 1.0);
  
    moaConfig.adaptive_threshold = {
      ...moaConfig.adaptive_threshold,
      processing_time: newProcessingTime,
      output_quality: newOutputQuality,
    };
  
    console.log('Recalculated adaptive thresholds:', moaConfig.adaptive_threshold);
  }
  
  /**
   * Updates visualization settings based on the current MOA configuration.
   * 
   * How it works:
   * 1. Retrieves current visualization settings
   * 2. Adjusts update interval based on the number of layers
   * 3. Updates the moaConfig with new visualization settings
   * 
   * Usage example:
   * ```javascript
   * // After updating layers or other relevant settings
   * updateVisualizationSettings();
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in updateMOAConfig)
   * 
   * Role in overall program logic:
   * This function ensures that the visualization settings are optimized
   * for the current MOA configuration, improving performance and user experience.
   * 
   * [Documentation](./docs/config.md#updateVisualizationSettings)
   */
  function updateVisualizationSettings() {
    // Implement logic to update visualization settings
    const { update_interval } = moaConfig.visualization || {};
  
    // Example adjustment
    const newUpdateInterval = (update_interval || 1000) + moaConfig.layers.length * 500;
  
    moaConfig.visualization = {
      ...moaConfig.visualization,
      update_interval: newUpdateInterval,
    };
  
    console.log('Updated visualization settings:', moaConfig.visualization);
  }
  
  /**
   * Updates the MOA controls in the user interface based on the current configuration.
   * 
   * How it works:
   * 1. Updates main model selection
   * 2. Updates main temperature control
   * 3. Updates adaptive threshold controls
   * 4. Updates self-evolving controls
   * 5. Updates function calling controls
   * 6. Updates controls for layers and agents (not fully implemented in this snippet)
   * 
   * Usage example:
   * ```javascript
   * // After updating the MOA configuration
   * updateMOAControls();
   * ```
   * 
   * Files that use this function:
   * - js/config/config.js (internal use in updateMOAConfig)
   * - js/ui/config-panel.js (potentially, for manual UI updates)
   * 
   * Role in overall program logic:
   * This function ensures that the user interface accurately reflects
   * the current MOA configuration, maintaining consistency between
   * the internal state and what the user sees.
   * 
   * [Documentation](./docs/config.md#updateMOAControls)
   */
  function updateMOAControls() {
    // Update main model select
    const mainModelSelect = document.getElementById('main-model-select');
    if (mainModelSelect) {
      mainModelSelect.value = moaConfig.main_model;
    }
  
    // Update main temperature
    const mainTemperature = document.getElementById('main-temperature');
    if (mainTemperature) {
      mainTemperature.value = moaConfig.main_temperature;
      const mainTempValue = document.getElementById('main-temperature-value');
      if (mainTempValue) {
        mainTempValue.textContent = moaConfig.main_temperature;
      }
    }
  
    // Update adaptive threshold controls
    const processingTime = document.getElementById('processing-time');
    if (processingTime) {
      processingTime.value = moaConfig.adaptive_threshold.processing_time;
      const processingTimeValue = document.getElementById('processing-time-value');
      if (processingTimeValue) {
        processingTimeValue.textContent = moaConfig.adaptive_threshold.processing_time;
      }
    }
  
    const outputQuality = document.getElementById('output-quality');
    if (outputQuality) {
      outputQuality.value = moaConfig.adaptive_threshold.output_quality;
      const outputQualityValue = document.getElementById('output-quality-value');
      if (outputQualityValue) {
        outputQualityValue.textContent = moaConfig.adaptive_threshold.output_quality;
      }
    }
  
    // Update self-evolving controls
    const selfEvolvingEnabled = document.getElementById('self-evolving-enabled');
    if (selfEvolvingEnabled) {
      selfEvolvingEnabled.checked = moaConfig.self_evolving.enabled;
    }
  
    const learningRate = document.getElementById('learning-rate');
    if (learningRate) {
      learningRate.value = moaConfig.self_evolving.learning_rate;
      const learningRateValue = document.getElementById('learning-rate-value');
      if (learningRateValue) {
        learningRateValue.textContent = moaConfig.self_evolving.learning_rate;
      }
    }
  
    // Update function calling controls
    const functionCallingEnabled = document.getElementById('function-calling-enabled');
    if (functionCallingEnabled) {
      functionCallingEnabled.checked = moaConfig.function_calling.enabled;
    }
  
    const functionCallingModel = document.getElementById('function-calling-model');
    if (functionCallingModel) {
      functionCallingModel.value = moaConfig.function_calling.model;
    }
  
    // Update controls for layers and agents
    // This would involve dynamically creating or updating controls based on moaConfig.layers
    // Implement this as per your UI structure
  }
  
  // Initialize moaConfig.connections if not already set
  if (!moaConfig.connections) {
    moaConfig.connections = [];
  }
