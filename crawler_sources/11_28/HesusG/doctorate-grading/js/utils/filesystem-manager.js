/**
 * FileSystemManager - Handles immediate persistence using localStorage + auto-download
 * Provides database-like immediate writes with Word-like save indicators
 */

export class FileSystemManager {
    constructor() {
        this.data = null;
        this.lastSaved = null;
        this.storageKey = 'doctorate_app_data';
        this.hasChanges = false;
        this.changeCount = 0;
        this.autoDownloadThreshold = 5; // Auto-suggest download after 5 changes
        this.reminderInterval = 300000; // 5 minutes
        this.reminderTimer = null;
    }

    /**
     * Initialize the file manager
     */
    async initialize() {
        this.createSaveIndicator();
        this.startReminderTimer();
        console.log('✅ FileSystemManager initialized with localStorage persistence');
        return true;
    }

    /**
     * Create the save indicator ribbon at the top of the page
     */
    createSaveIndicator() {
        // Create save indicator ribbon
        const ribbon = document.createElement('div');
        ribbon.id = 'saveIndicatorRibbon';
        ribbon.className = 'save-indicator-ribbon hidden';
        ribbon.innerHTML = `
            <div class="save-indicator-content">
                <div class="save-indicator-left">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span id="saveIndicatorText">Tienes cambios sin guardar</span>
                    <span id="changeCounter">(0 cambios)</span>
                </div>
                <div class="save-indicator-right">
                    <button id="discardChangesBtn" class="discard-btn">
                        <i class="fas fa-undo"></i> Descartar Cambios
                    </button>
                    <button id="downloadDataBtn" class="save-btn">
                        <i class="fas fa-download"></i> Descargar universidades.js
                    </button>
                    <button id="dismissReminderBtn" class="dismiss-btn">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
        `;

        // Insert at the very top of body, above everything
        document.body.insertBefore(ribbon, document.body.firstChild);

        // Add event listeners
        document.getElementById('downloadDataBtn').addEventListener('click', () => {
            this.downloadUpdatedFile();
        });

        document.getElementById('discardChangesBtn').addEventListener('click', () => {
            this.discardChanges();
        });

        document.getElementById('dismissReminderBtn').addEventListener('click', () => {
            this.hideSaveIndicator();
        });
    }

    /**
     * Show save indicator
     */
    showSaveIndicator() {
        const ribbon = document.getElementById('saveIndicatorRibbon');
        if (ribbon) {
            ribbon.classList.remove('hidden');
            this.updateChangeCounter();
            // Add padding to push content down
            document.body.style.paddingTop = '60px';
        }
    }

    /**
     * Hide save indicator
     */
    hideSaveIndicator() {
        const ribbon = document.getElementById('saveIndicatorRibbon');
        if (ribbon) {
            ribbon.classList.add('hidden');
            // Remove padding when hidden
            document.body.style.paddingTop = '0';
        }
    }

    /**
     * Update change counter display
     */
    updateChangeCounter() {
        const counter = document.getElementById('changeCounter');
        if (counter) {
            counter.textContent = `(${this.changeCount} cambio${this.changeCount !== 1 ? 's' : ''})`;
        }
    }

    /**
     * Start reminder timer
     */
    startReminderTimer() {
        if (this.reminderTimer) {
            clearInterval(this.reminderTimer);
        }

        this.reminderTimer = setInterval(() => {
            if (this.hasChanges) {
                this.showSaveReminder();
            }
        }, this.reminderInterval);
    }

    /**
     * Show save reminder notification
     */
    showSaveReminder() {
        const reminder = document.createElement('div');
        reminder.className = 'save-reminder-notification';
        reminder.innerHTML = `
            <div class="reminder-content">
                <i class="fas fa-save"></i>
                <span>Recordatorio: Tienes ${this.changeCount} cambios sin guardar</span>
                <button onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
        `;

        document.body.appendChild(reminder);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (reminder.parentElement) {
                reminder.remove();
            }
        }, 5000);
    }

    /**
     * Load data from localStorage or original universidades.js module
     */
    async loadData(universidadesData) {
        // Try to load from localStorage first
        const savedData = localStorage.getItem(this.storageKey);
        
        if (savedData) {
            try {
                this.data = JSON.parse(savedData);
                this.hasChanges = true;
                this.changeCount = parseInt(localStorage.getItem(this.storageKey + '_changes') || '0');
                this.showSaveIndicator();
                console.log(`📊 Loaded ${this.data.length} records from localStorage (${this.changeCount} changes pending)`);
            } catch (error) {
                console.error('Failed to parse saved data, using original:', error);
                this.data = [...universidadesData];
                localStorage.removeItem(this.storageKey);
            }
        } else {
            this.data = [...universidadesData]; // Create a copy
            console.log(`📊 Loaded ${this.data.length} records from original data`);
        }
        
        return this.data;
    }

    /**
     * Update a single record and save to localStorage
     */
    async updateRecord(recordId, changes) {
        if (!this.data) {
            throw new Error('Data not loaded. Call loadData() first.');
        }

        // Find and update the record
        const recordIndex = this.data.findIndex(record => record._id === recordId);
        if (recordIndex === -1) {
            throw new Error(`Record with ID ${recordId} not found`);
        }

        // Deep merge changes into the record
        const updatedRecord = this.deepMerge(this.data[recordIndex], changes);
        
        // Update the updated_date
        updatedRecord.updated_date = new Date().toISOString();
        
        // Replace the record in the array
        this.data[recordIndex] = updatedRecord;

        // Save to localStorage and update indicators
        this.saveToLocalStorage();

        console.log(`✅ Updated record ${recordId} and saved to localStorage`);
        return updatedRecord;
    }

    /**
     * Save data to localStorage and update indicators
     */
    saveToLocalStorage() {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(this.data));
            this.changeCount++;
            localStorage.setItem(this.storageKey + '_changes', this.changeCount.toString());
            localStorage.setItem(this.storageKey + '_timestamp', new Date().toISOString());
            
            this.hasChanges = true;
            this.lastSaved = new Date().toISOString();
            this.showSaveIndicator();
            
            // Auto-suggest download after threshold
            if (this.changeCount >= this.autoDownloadThreshold && this.changeCount % this.autoDownloadThreshold === 0) {
                this.suggestDownload();
            }
            
        } catch (error) {
            console.error('Failed to save to localStorage:', error);
            throw new Error('No se pudo guardar los cambios en el almacenamiento local');
        }
    }

    /**
     * Suggest download to user
     */
    suggestDownload() {
        const suggestion = document.createElement('div');
        suggestion.className = 'download-suggestion';
        suggestion.innerHTML = `
            <div class="suggestion-content">
                <i class="fas fa-download"></i>
                <div class="suggestion-text">
                    <strong>¡Tiempo de guardar!</strong>
                    <p>Tienes ${this.changeCount} cambios. Descarga el archivo actualizado.</p>
                </div>
                <div class="suggestion-actions">
                    <button onclick="window.app.getModalComponent().fileSystemManager.downloadUpdatedFile()" class="suggestion-btn primary">
                        Descargar Ahora
                    </button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" class="suggestion-btn secondary">
                        Más Tarde
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(suggestion);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (suggestion.parentElement) {
                suggestion.remove();
            }
        }, 10000);
    }

    /**
     * Download updated universidades.js file
     */
    downloadUpdatedFile() {
        try {
            // Format data as ES module
            const fileContent = `export const universidadesData = 
${JSON.stringify(this.data, null, 2)};`;

            // Create download
            const blob = new Blob([fileContent], { type: 'text/javascript' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = 'universidades.js';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // Reset change tracking
            this.markAsSaved();

            console.log(`✅ Downloaded universidades.js with ${this.data.length} records`);
            
        } catch (error) {
            console.error('Failed to download file:', error);
            alert('Error al descargar el archivo. Por favor intenta de nuevo.');
        }
    }

    /**
     * Mark data as saved (reset change tracking)
     */
    markAsSaved() {
        this.hasChanges = false;
        this.changeCount = 0;
        localStorage.removeItem(this.storageKey);
        localStorage.removeItem(this.storageKey + '_changes');
        localStorage.removeItem(this.storageKey + '_timestamp');
        this.hideSaveIndicator();
    }

    /**
     * Discard all unsaved changes and revert to original data
     */
    async discardChanges() {
        try {
            // Show confirmation dialog
            const confirmed = confirm('¿Estás seguro de que quieres descartar todos los cambios no guardados?\n\nEsto revertirá todos los cambios realizados desde la última descarga.');
            
            if (confirmed) {
                // Clear localStorage
                localStorage.removeItem(this.storageKey);
                localStorage.removeItem(this.storageKey + '_changes');
                localStorage.removeItem(this.storageKey + '_timestamp');
                
                // Reset change tracking
                this.hasChanges = false;
                this.changeCount = 0;
                this.hideSaveIndicator();
                
                // Reload the page to refresh all components with original data
                window.location.reload();
                
                console.log('✅ Changes discarded successfully');
            }
        } catch (error) {
            console.error('Failed to discard changes:', error);
            alert('Error al descartar cambios. Por favor intenta de nuevo.');
        }
    }

    /**
     * Toggle favorite status for a record
     */
    async toggleFavorite(recordId) {
        const record = this.data.find(r => r._id === recordId);
        if (!record) {
            throw new Error(`Record with ID ${recordId} not found`);
        }

        const newFavoriteStatus = !record.program.is_favorite;
        
        return await this.updateRecord(recordId, {
            program: {
                is_favorite: newFavoriteStatus
            }
        });
    }

    /**
     * Update program rating
     */
    async updateRating(recordId, rating, comment = '') {
        return await this.updateRecord(recordId, {
            program: {
                rating: {
                    overall: rating,
                    date: new Date().toISOString(),
                    comment: comment
                }
            }
        });
    }

    /**
     * Update program criteria
     */
    async updateCriteria(recordId, criterion, value) {
        const changes = {
            program: {
                criteria: {
                    [criterion]: value
                }
            }
        };
        
        return await this.updateRecord(recordId, changes);
    }

    /**
     * Update program field (name, url, status, etc.)
     */
    async updateProgramField(recordId, field, value) {
        const changes = {
            program: {
                [field]: value
            }
        };
        
        return await this.updateRecord(recordId, changes);
    }

    /**
     * Get current data
     */
    getData() {
        return this.data;
    }

    /**
     * Get record by ID
     */
    getRecord(recordId) {
        return this.data.find(record => record._id === recordId);
    }

    /**
     * Export data as JSON for sharing
     */
    exportAsJSON() {
        return JSON.stringify(this.data, null, 2);
    }

    /**
     * Import data from JSON
     */
    async importFromJSON(jsonData) {
        try {
            const importedData = JSON.parse(jsonData);
            
            // Validate data structure
            if (!Array.isArray(importedData)) {
                throw new Error('Invalid data format: expected array');
            }

            // Basic validation of records
            for (const record of importedData) {
                if (!record._id || !record.program) {
                    throw new Error('Invalid record structure');
                }
            }

            this.data = importedData;
            await this.writeToFile();
            
            console.log(`✅ Imported ${importedData.length} records and saved to file`);
            return this.data;
        } catch (error) {
            console.error('Failed to import data:', error);
            throw error;
        }
    }

    /**
     * Write current data to file in ES module format
     */
    async writeToFile() {
        if (!this.fileHandle) {
            throw new Error('No file handle available. Call initializeFileAccess() first.');
        }

        try {
            // Format data as ES module
            const fileContent = `export const universidadesData = 
${JSON.stringify(this.data, null, 2)};`;

            // Create writable stream
            const writable = await this.fileHandle.createWritable();
            
            // Write the content
            await writable.write(fileContent);
            
            // Close the stream
            await writable.close();

            this.lastSaved = new Date().toISOString();
            console.log(`💾 Successfully wrote ${this.data.length} records to file`);
            
        } catch (error) {
            console.error('Failed to write to file:', error);
            throw error;
        }
    }

    /**
     * Deep merge two objects
     */
    deepMerge(target, source) {
        const result = JSON.parse(JSON.stringify(target)); // Deep copy
        
        function merge(obj, src) {
            for (const key in src) {
                if (src.hasOwnProperty(key)) {
                    if (src[key] && typeof src[key] === 'object' && !Array.isArray(src[key])) {
                        if (!obj[key] || typeof obj[key] !== 'object') {
                            obj[key] = {};
                        }
                        merge(obj[key], src[key]);
                    } else {
                        obj[key] = src[key];
                    }
                }
            }
        }
        
        merge(result, source);
        return result;
    }

    /**
     * Get file system status
     */
    getStatus() {
        return {
            isSupported: this.isSupported,
            hasFileAccess: !!this.fileHandle,
            recordCount: this.data ? this.data.length : 0,
            lastSaved: this.lastSaved,
            fileName: this.fileHandle ? this.fileHandle.name : null
        };
    }
}