
/**
 * @file chat.ts
 *
 * This file implements the main chat interface for the AI Assistant plugin in Obsidian.
 * It defines the ChatView class, which manages the chat UI, message flow, streaming responses,
 * tool/agent integration, and persistent chat history. The view supports advanced features such as
 * agent mode (tool use), reference note context, message regeneration, and real-time tool result display.
 *
 * Key responsibilities:
 * - Rendering and updating the chat UI
 * - Handling user input and assistant responses (including streaming)
 * - Integrating with tools/agents for advanced AI actions
 * - Persisting and restoring chat history
 * - Managing context (system prompt, reference note, etc.)
 * - Supporting message regeneration and error handling
 */

import { ItemView, WorkspaceLeaf, Notice } from 'obsidian';
import MyPlugin from './main';
import { Message, ToolCommand, ToolResult } from './types';
import { ChatHistoryManager, ChatMessage } from './components/chat/ChatHistoryManager';
import { createMessageElement } from './components/chat/Message';
import { createChatUI, ChatUIElements } from './components/chat/ui';
import { handleCopyAll, handleSaveNote, handleClearChat, handleSettings, handleHelp } from './components/chat/eventHandlers';
import { loadChatYamlAndApplySettings } from './components/chat/chatPersistence';
import { renderChatHistory } from './components/chat/chatHistoryUtils';
import { AgentResponseHandler } from './components/agent/AgentResponseHandler';
import { buildContextMessages } from './utils/contextBuilder';
import { MessageRegenerator } from './components/chat/MessageRegenerator';
import { ResponseStreamer } from './components/chat/ResponseStreamer';
import { MessageRenderer } from './components/agent/MessageRenderer';
import { ToolRichDisplay } from './components/agent/ToolRichDisplay';
import { MessageContextPool, WeakCache, PreAllocatedArrays } from './utils/objectPool';
import { DOMBatcher } from './utils/domBatcher';
import { handleChatError, withErrorHandling } from './utils/errorHandler';
import { AsyncDebouncer, AsyncOptimizerFactory } from './utils/asyncOptimizer';
export const VIEW_TYPE_CHAT = 'chat-view';
export class ChatView extends ItemView {
    private plugin: MyPlugin;
    private chatHistoryManager: ChatHistoryManager;
    private messagesContainer: HTMLElement;
    private inputContainer: HTMLElement;
    private activeStream: AbortController | null = null;
    private referenceNoteIndicator: HTMLElement;
    private modelNameDisplay: HTMLElement;
    private agentResponseHandler: AgentResponseHandler | null = null;
    private messageRegenerator: MessageRegenerator | null = null;
    private responseStreamer: ResponseStreamer | null = null;
    private messageRenderer: MessageRenderer;
    private messagePool: MessageContextPool;
    private domCache: WeakCache<HTMLElement, any>;
    private arrayManager: PreAllocatedArrays;
    private cachedMessageElements: HTMLElement[] = [];
    private lastScrollHeight: number = 0;
    private domElementCache: {
        textarea?: HTMLTextAreaElement;
        sendButton?: HTMLButtonElement;
        stopButton?: HTMLButtonElement;
        copyAllButton?: HTMLButtonElement;
        clearButton?: HTMLButtonElement;
        settingsButton?: HTMLButtonElement;
        helpButton?: HTMLButtonElement;
        saveNoteButton?: HTMLButtonElement;
        referenceNoteButton?: HTMLButtonElement;
        agentModeButton?: HTMLButtonElement;
        toolContinuationContainer?: HTMLElement;
    } = {};
    private eventListeners: Array<{
        element: HTMLElement;
        event: string;
        handler: EventListener;
    }> = [];
    private domBatcher: DOMBatcher;
    
    // Priority 2 Optimization: Async optimization
    private scrollDebouncer: AsyncDebouncer<void>;
    private updateDebouncer: AsyncDebouncer<void>;
    constructor(leaf: WorkspaceLeaf, plugin: MyPlugin) {
        super(leaf);
        this.plugin = plugin;
        this.chatHistoryManager = new ChatHistoryManager(this.app.vault, this.plugin.manifest.id, "chat-history.json");
        this.messageRenderer = new MessageRenderer(this.app);
        this.messagePool = MessageContextPool.getInstance();
        this.domCache = new WeakCache();
        this.arrayManager = PreAllocatedArrays.getInstance();
        this.domBatcher = new DOMBatcher();
        
        // Priority 2 Optimization: Initialize async optimizers
        this.scrollDebouncer = AsyncOptimizerFactory.createInputDebouncer();
        this.updateDebouncer = AsyncOptimizerFactory.createInputDebouncer();
    }
    private addEventListenerWithCleanup(element: HTMLElement, event: string, handler: EventListener): void {
        element.addEventListener(event, handler);
        this.eventListeners.push({ element, event, handler });
    }
    private cacheUIElements(ui: any): void {
        this.domElementCache.textarea = ui.textarea;
        this.domElementCache.sendButton = ui.sendButton;
        this.domElementCache.stopButton = ui.stopButton;
        this.domElementCache.copyAllButton = ui.copyAllButton;
        this.domElementCache.clearButton = ui.clearButton;
        this.domElementCache.settingsButton = ui.settingsButton;
        this.domElementCache.helpButton = ui.helpButton;
        this.domElementCache.saveNoteButton = ui.saveNoteButton;
        this.domElementCache.referenceNoteButton = ui.referenceNoteButton;
        this.domElementCache.agentModeButton = ui.agentModeButton;
        this.domElementCache.toolContinuationContainer = ui.toolContinuationContainer;
    }
    getViewType(): string {
        return VIEW_TYPE_CHAT;
    }
    getDisplayText(): string {
        return 'AI Chat';
    }
    getIcon(): string {
        return 'message-square';
    }
    async onOpen() {
        const { contentEl } = this;
        this.prepareChatView(contentEl);
        const loadedHistory = await this.loadChatHistory();
        const ui: ChatUIElements = createChatUI(this.app, contentEl);
        this.initializeUIElements(ui);
        this.setupEventHandlers(ui);
        this.setupAgentResponseHandler();
        this.setupResponseStreamerAndRegenerator();
        this.setupAgentModeButton();
        this.setupSendAndStopButtons();
        this.setupInputHandler(ui);
        await this.loadAndRenderHistory(loadedHistory);
        this.updateReferenceNoteIndicator();
        this.registerWorkspaceAndSettingsEvents();
    }

    private prepareChatView(contentEl: HTMLElement) {
        contentEl.empty();
        contentEl.addClass('ai-chat-view');
    }

    private async loadChatHistory(): Promise<ChatMessage[]> {
        return await withErrorHandling(
            () => this.chatHistoryManager.getHistory(),
            'ChatView',
            'loadChatHistory',
            { fallbackMessage: 'Failed to load chat history' }
        ) || [];
    }

    private initializeUIElements(ui: ChatUIElements) {
        this.messagesContainer = ui.messagesContainer;
        this.inputContainer = ui.inputContainer;
        this.referenceNoteIndicator = ui.referenceNoteIndicator;
        this.modelNameDisplay = ui.modelNameDisplay;
        this.cacheUIElements(ui);
        this.updateReferenceNoteIndicator();
        this.updateModelNameDisplay();
    }

    private setupEventHandlers(ui: ChatUIElements) {
        this.addEventListenerWithCleanup(this.domElementCache.copyAllButton!, 'click', handleCopyAll(this.messagesContainer, this.plugin));
        this.addEventListenerWithCleanup(this.domElementCache.clearButton!, 'click', handleClearChat(this.messagesContainer, this.chatHistoryManager));
        this.addEventListenerWithCleanup(this.domElementCache.settingsButton!, 'click', handleSettings(this.app, this.plugin));
        this.addEventListenerWithCleanup(this.domElementCache.helpButton!, 'click', handleHelp(this.app));
        this.addEventListenerWithCleanup(this.domElementCache.referenceNoteButton!, 'click', () => {
            this.plugin.settings.referenceCurrentNote = !this.plugin.settings.referenceCurrentNote;
            this.plugin.saveSettings();
            this.updateReferenceNoteIndicator();
        });
        this.addEventListenerWithCleanup(this.domElementCache.saveNoteButton!, 'click', handleSaveNote(this.messagesContainer, this.plugin, this.app, this.agentResponseHandler));
    }

    private setupAgentResponseHandler() {
        this.agentResponseHandler = new AgentResponseHandler({
            app: this.app,
            plugin: this.plugin,
            messagesContainer: this.messagesContainer,
            toolContinuationContainer: this.domElementCache.toolContinuationContainer!,
            onToolResult: (toolResult: ToolResult, command: ToolCommand) => {
                if (toolResult.success) {
                    this.plugin.debugLog('info', `[chat.ts] Tool ${command.action} completed successfully`, toolResult.data);
                } else {
                    this.plugin.debugLog('error', `[chat.ts] Tool ${command.action} failed:`, toolResult.error);
                }
            },
            onToolDisplay: (display: ToolRichDisplay) => {
                const toolWrapper = document.createElement('div');
                toolWrapper.className = 'real-time-tool-display';
                toolWrapper.appendChild(display.getElement());
                const tempContainer = this.messagesContainer.querySelector('.ai-chat-message.assistant:last-child');
                if (tempContainer) {
                    const messageContent = tempContainer.querySelector('.message-content');
                    if (messageContent) {
                        messageContent.appendChild(toolWrapper);
                        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
                    }
                }
            }
        });
    }

    private setupResponseStreamerAndRegenerator() {
        this.responseStreamer = new ResponseStreamer(
            this.plugin,
            this.agentResponseHandler,
            this.messagesContainer,
            this.activeStream,
            this
        );
        this.messageRegenerator = new MessageRegenerator(
            this.plugin,
            this.messagesContainer,
            this.inputContainer,
            this.chatHistoryManager,
            this.agentResponseHandler,
            this.activeStream
        );
    }

    private setupAgentModeButton() {
        this.addEventListenerWithCleanup(this.domElementCache.agentModeButton!, 'click', async () => {
            const isCurrentlyEnabled = this.plugin.agentModeManager.isAgentModeEnabled();
            await this.plugin.agentModeManager.setAgentModeEnabled(!isCurrentlyEnabled);
            const agentButton = this.domElementCache.agentModeButton!;
            if (this.plugin.agentModeManager.isAgentModeEnabled()) {
                agentButton.classList.add('active');
                agentButton.setAttribute('title', 'Agent Mode: ON - AI can use tools');
                new Notice('Agent Mode enabled - AI can now use tools');
                if (this.agentResponseHandler) {
                    this.agentResponseHandler.resetExecutionCount();
                }
            } else {
                agentButton.classList.remove('active');
                agentButton.setAttribute('title', 'Agent Mode: OFF - Regular chat');
                new Notice('Agent Mode disabled');
            }
        });
        const agentButton = this.domElementCache.agentModeButton!;
        if (this.plugin.agentModeManager.isAgentModeEnabled()) {
            agentButton.classList.add('active');
            agentButton.setAttribute('title', 'Agent Mode: ON - AI can use tools');
        } else {
            agentButton.classList.remove('active');
            agentButton.setAttribute('title', 'Agent Mode: OFF - Regular chat');
        }
    }

    private setupSendAndStopButtons() {
        const textarea = this.domElementCache.textarea!;
        const sendButton = this.domElementCache.sendButton!;
        const stopButton = this.domElementCache.stopButton!;
        const sendMessage = async () => {
            const content = textarea.value.trim();
            if (!content) return;
            if (this.agentResponseHandler) {
                this.agentResponseHandler.resetExecutionCount();
            }
            textarea.disabled = true;
            sendButton.classList.add('hidden');
            stopButton.classList.remove('hidden');
            const userMessageEl = await createMessageElement(this.app, 'user', content, this.chatHistoryManager, this.plugin, (el: HTMLElement) => this.regenerateResponse(el), this);
            this.messagesContainer.appendChild(userMessageEl);
            this.debouncedScrollToBottom();
            textarea.value = '';
            await withErrorHandling(
                () => this.chatHistoryManager.addMessage({
                    timestamp: userMessageEl.dataset.timestamp || new Date().toISOString(),
                    sender: 'user',
                    role: 'user',
                    content: content
                }),
                'ChatView',
                'saveUserMessage',
                { fallbackMessage: 'Failed to save user message' }
            );
            try {
                const messages = await this.buildContextMessages();
                this.addVisibleMessagesToContext(messages);
                const tempContainer = document.createElement('div');
                tempContainer.addClass('ai-chat-message', 'assistant');
                tempContainer.createDiv('message-content');
                this.messagesContainer.appendChild(tempContainer);
                this.debouncedScrollToBottom();
                const responseContent = await this.streamAssistantResponse(messages, tempContainer);
                let enhancedMessageData: any = undefined;
                this.plugin.debugLog('debug', '[chat.ts] tempContainer.dataset.messageData exists:', !!tempContainer.dataset.messageData);
                if (tempContainer.dataset.messageData) {
                    try {
                        enhancedMessageData = JSON.parse(tempContainer.dataset.messageData);
                        this.plugin.debugLog('debug', '[chat.ts] enhancedMessageData parsed, toolResults count:', enhancedMessageData.toolResults?.length || 0);
                    } catch (e) {
                        this.plugin.debugLog('warn', '[chat.ts] Failed to parse enhanced message data:', e);
                    }
                }
                this.plugin.debugLog('debug', '[chat.ts] responseContent length:', responseContent.length, 'trimmed length:', responseContent.trim().length);
                tempContainer.remove();
                if (responseContent.trim() !== "" || (enhancedMessageData && enhancedMessageData.toolResults && enhancedMessageData.toolResults.length > 0)) {
                    const messageEl = await createMessageElement(
                        this.app,
                        'assistant',
                        responseContent,
                        this.chatHistoryManager,
                        this.plugin,
                        (el) => this.regenerateResponse(el),
                        this,
                        enhancedMessageData
                    );
                    this.messagesContainer.appendChild(messageEl);
                    this.plugin.debugLog('debug', '[chat.ts] About to save message to history with toolResults:', !!enhancedMessageData?.toolResults);
                    await this.chatHistoryManager.addMessage({
                        timestamp: messageEl.dataset.timestamp || new Date().toISOString(),
                        sender: 'assistant',
                        content: responseContent,
                        ...(enhancedMessageData && {
                            toolResults: enhancedMessageData.toolResults,
                            reasoning: enhancedMessageData.reasoning,
                            taskStatus: enhancedMessageData.taskStatus
                        })
                    });
                    this.plugin.debugLog('debug', '[chat.ts] Message saved to history successfully');
                } else {
                    this.plugin.debugLog('debug', '[chat.ts] responseContent is empty and no toolResults, not saving message');
                }
            } catch (error) {
                if (error.name !== 'AbortError') {
                    handleChatError(error, 'sendMessage', {
                        messageLength: content.length,
                        agentMode: this.plugin.agentModeManager.isAgentModeEnabled()
                    });
                    await createMessageElement(this.app, 'assistant', `Error: ${error.message}`, this.chatHistoryManager, this.plugin, (el: HTMLElement) => this.regenerateResponse(el), this);
                }
            } finally {
                textarea.disabled = false;
                textarea.focus();
                stopButton.classList.add('hidden');
                sendButton.classList.remove('hidden');
                this.activeStream = null;
            }
        };
        this.addEventListenerWithCleanup(sendButton, 'click', sendMessage);
        this.addEventListenerWithCleanup(stopButton, 'click', () => {
            const myPlugin = this.plugin as any;
            if (myPlugin.stopAllAIStreams && typeof myPlugin.stopAllAIStreams === 'function') {
                myPlugin.stopAllAIStreams();
            }
            if (this.activeStream) {
                this.activeStream.abort();
                this.activeStream = null;
            }
            textarea.disabled = false;
            textarea.focus();
            stopButton.classList.add('hidden');
            sendButton.classList.remove('hidden');
        });
    }

    private setupInputHandler(ui: ChatUIElements) {
        const textarea = this.domElementCache.textarea!;
        const sendButton = this.domElementCache.sendButton!;
        const stopButton = this.domElementCache.stopButton!;
        import('./components/chat/inputHandler').then(({ setupInputHandler }) => {
            setupInputHandler(
                textarea,
                this.messagesContainer,
                async () => sendButton.click(),
                async (cmd: string) => {
                    switch (cmd) {
                        case '/clear':
                            ui.clearButton.click();
                            break;
                        case '/copy':
                            ui.copyAllButton.click();
                            break;
                        case '/save':
                            ui.saveNoteButton.click();
                            break;
                        case '/settings':
                            ui.settingsButton.click();
                            break;
                        case '/help':
                            ui.helpButton.click();
                            break;
                        case '/ref':
                            ui.referenceNoteButton.click();
                            break;
                    }
                },
                this.app,
                this.plugin,
                sendButton,
                stopButton
            );
        });
    }

    private async loadAndRenderHistory(loadedHistory: ChatMessage[]) {
        if (loadedHistory.length > 0) {
            this.messagesContainer.empty();
            const file = this.app.workspace.getActiveFile();
            if (file) {
                await loadChatYamlAndApplySettings({
                    app: this.app,
                    plugin: this.plugin,
                    settings: this.plugin.settings,
                    file
                });
            }
            await renderChatHistory({
                messagesContainer: this.messagesContainer,
                loadedHistory,
                chatHistoryManager: this.chatHistoryManager,
                plugin: this.plugin,
                regenerateResponse: (el: HTMLElement) => this.regenerateResponse(el),
                scrollToBottom: true
            });
        }
    }

    private registerWorkspaceAndSettingsEvents() {
        this.registerEvent(this.app.workspace.on('active-leaf-change', () => {
            this.updateReferenceNoteIndicator();
        }));
        this.plugin.onSettingsChange(() => {
            this.updateReferenceNoteIndicator();
            this.updateModelNameDisplay();
        });
    }
    private async addMessage(role: 'user' | 'assistant', content: string, isError: boolean = false, enhancedData?: Partial<Pick<Message, 'reasoning' | 'taskStatus' | 'toolResults'>>): Promise<void> {
        const messageEl = await createMessageElement(this.app, role, content, this.chatHistoryManager, this.plugin, (el: HTMLElement) => this.regenerateResponse(el), this, enhancedData ? { role, content, ...enhancedData } : undefined);
        const uiTimestamp = messageEl.dataset.timestamp || new Date().toISOString();
        this.messagesContainer.appendChild(messageEl);
        this.debouncedScrollToBottom();
        await withErrorHandling(
            () => this.chatHistoryManager.addMessage({
                timestamp: uiTimestamp,
                sender: role,
                role: role,
                content,
                ...(enhancedData || {})
            }),
            'ChatView',
            'addMessage',
            { fallbackMessage: 'Failed to save chat message' }
        );
    }
    async onClose() {
        if (this.activeStream) {
            this.activeStream.abort();
            this.activeStream = null;
        }
        this.cleanupEventListeners();
        this.cleanupMemoryResources();
    }
    private cleanupEventListeners(): void {
        for (const { element, event, handler } of this.eventListeners) {
            element.removeEventListener(event, handler);
        }
        this.eventListeners.length = 0;
    }
    private cleanupMemoryResources(): void {
        this.cachedMessageElements.length = 0;
        this.lastScrollHeight = 0;
        this.domElementCache = {};
        if (this.domBatcher) {
            this.domBatcher.clear();
        }
    }
    private async regenerateResponse(messageEl: HTMLElement) {
        if (this.messageRegenerator) {
            await this.messageRegenerator.regenerateResponse(messageEl, () => this.buildContextMessages());
        }
    }
    private updateReferenceNoteIndicator() {
        this.updateDebouncer.debounce(async () => {
            const currentFile = this.app.workspace.getActiveFile();
            const isReferenceEnabled = this.plugin.settings.referenceCurrentNote;
            const button = this.referenceNoteIndicator.previousElementSibling as HTMLButtonElement;
            if (isReferenceEnabled && currentFile) {
                this.referenceNoteIndicator.setText(`📝 Referencing: ${currentFile.basename}`);
                this.referenceNoteIndicator.style.display = 'block';
                if (button && button.getAttribute('aria-label') === 'Toggle referencing current note') {
                    button.setText('📝');
                    button.classList.add('active');
                }
            } else {
                this.referenceNoteIndicator.style.display = 'none';
                if (button && button.getAttribute('aria-label') === 'Toggle referencing current note') {
                    button.setText('📝');
                    button.classList.remove('active');
                }
            }
        });
    }
    private updateModelNameDisplay() {
        if (!this.modelNameDisplay) return;
        let modelName = 'Unknown Model';
        const settings = this.plugin.settings;
        if (settings.selectedModel && settings.availableModels) {
            const found = settings.availableModels.find((m: any) => m.id === settings.selectedModel);
            if (found) modelName = found.name;
            else modelName = settings.selectedModel;
        } else if (settings.selectedModel) {
            modelName = settings.selectedModel;
        }
        this.modelNameDisplay.textContent = `Model: ${modelName}`;
    }
    private async buildContextMessages(): Promise<Message[]> {
        return await buildContextMessages({ app: this.app, plugin: this.plugin });
    }
    private addVisibleMessagesToContext(messages: Message[]): void {
        const currentScrollHeight = this.messagesContainer.scrollHeight;
        let messageElements: NodeListOf<Element>;
        if (this.lastScrollHeight === currentScrollHeight && this.cachedMessageElements.length > 0) {
            messageElements = this.cachedMessageElements as any;
        } else {
            messageElements = this.messagesContainer.querySelectorAll('.ai-chat-message');
            this.cachedMessageElements = Array.from(messageElements) as HTMLElement[];
            this.lastScrollHeight = currentScrollHeight;
        }
        for (let i = 0; i < messageElements.length; i++) {
            const el = messageElements[i] as HTMLElement;
            const role = el.classList.contains('user') ? 'user' : 'assistant';
            const contentEl = el.querySelector('.message-content');
            const content = contentEl?.textContent || '';
            const messageObj = this.messagePool.acquireMessage();
            messageObj.role = role;
            messageObj.content = content;
            messages.push(messageObj as Message);
        }
    }
    private async streamAssistantResponse(
        messages: Message[],
        container: HTMLElement,
        originalTimestamp?: string,
        originalContent?: string
    ): Promise<string> {
        if (!this.responseStreamer) {
            throw new Error("ResponseStreamer not initialized");
        }
        const chatHistory = await this.chatHistoryManager.getHistory();
        const responseContent = await this.responseStreamer.streamAssistantResponse(
            messages,
            container,
            originalTimestamp,
            originalContent,
            chatHistory
        );
        if (originalTimestamp && responseContent.trim() !== "") {
            let messageData: any = undefined;
            if (container.dataset.messageData) {
                try {
                    messageData = JSON.parse(container.dataset.messageData);
                } catch { }
            }
            await this.chatHistoryManager.updateMessage(
                originalTimestamp,
                'assistant',
                originalContent || '',
                responseContent,
                messageData
            );
        }
        return responseContent;
    }
    public clearMessages() {
        this.messagesContainer.empty();
        if (this.agentResponseHandler) {
            this.agentResponseHandler.resetExecutionCount();
        }
    }
    public scrollMessagesToBottom() {
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
    stopActiveStream(): void {
        if (this.activeStream) {
            this.activeStream.abort();
            this.activeStream = null;
        }
        const myPlugin = this.plugin as any;
        if (myPlugin.aiDispatcher && typeof myPlugin.aiDispatcher.abortAllStreams === 'function') {
            myPlugin.aiDispatcher.abortAllStreams();
        }
    }
    hasActiveStream(): boolean {
        if (this.activeStream !== null) {
            return true;
        }
        const myPlugin = this.plugin as any;
        if (myPlugin.aiDispatcher && typeof myPlugin.aiDispatcher.hasActiveStreams === 'function') {
            return myPlugin.aiDispatcher.hasActiveStreams();
        }
        return false;
    }

    /**
     * Priority 2 Optimization: Debounced scroll to bottom
     */
    private debouncedScrollToBottom(): void {
        this.scrollDebouncer.debounce(async () => {
            this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
        });
    }

    /**
     * Priority 2 Optimization: Batch DOM updates for better performance
     */
    private batchDOMUpdates(elements: HTMLElement[], parent: HTMLElement): void {
        // Use the existing DOMBatcher API to add elements efficiently
        const operations = elements.map(element => ({
            element,
            parent
        }));
        this.domBatcher.addElements(operations);
    }
}
