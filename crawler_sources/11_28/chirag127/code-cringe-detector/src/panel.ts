import * as vscode from 'vscode';
import { CringeIssue, formatTimestamp, getHistory } from './utils';

/**
 * Manages the sidebar panel for displaying code smells
 */
export class CringePanel {
    public static currentPanel: CringePanel | undefined;
    private static readonly viewType = 'codeCringeDetector.panel';

    private readonly panel: vscode.WebviewPanel;
    private readonly context: vscode.ExtensionContext;
    private disposables: vscode.Disposable[] = [];
    private currentFileUri: string | undefined;

    /**
     * Create or show the panel
     */
    public static createOrShow(context: vscode.ExtensionContext): CringePanel {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        // If we already have a panel, show it
        if (CringePanel.currentPanel) {
            CringePanel.currentPanel.panel.reveal(column);
            return CringePanel.currentPanel;
        }

        // Otherwise, create a new panel
        const panel = vscode.window.createWebviewPanel(
            CringePanel.viewType,
            'Code Cringe Detector',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [
                    vscode.Uri.joinPath(context.extensionUri, 'media')
                ]
            }
        );

        CringePanel.currentPanel = new CringePanel(panel, context);
        return CringePanel.currentPanel;
    }

    /**
     * Private constructor for the panel
     */
    private constructor(panel: vscode.WebviewPanel, context: vscode.ExtensionContext) {
        this.panel = panel;
        this.context = context;

        // Set initial content
        this.update([]);

        // Listen for when the panel is disposed
        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        // Handle messages from the webview
        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'jumpToLine':
                        this.jumpToLine(message.line);
                        break;
                    case 'showHistory':
                        this.showHistory();
                        break;
                    case 'fixIssue':
                        this.requestFix(message.issue);
                        break;
                }
            },
            null,
            this.disposables
        );
    }

    /**
     * Update the panel with new issues
     */
    public update(issues: CringeIssue[], fileUri?: string): void {
        if (fileUri) {
            this.currentFileUri = fileUri;
        }

        this.panel.webview.html = this.getWebviewContent(issues);
    }

    /**
     * Show the history of scans
     */
    public showHistory(): void {
        if (!this.currentFileUri) {
            vscode.window.showErrorMessage('No file history available');
            return;
        }

        const history = getHistory(this.context, this.currentFileUri);
        
        if (history.length === 0) {
            vscode.window.showInformationMessage('No history available for this file');
            return;
        }

        this.panel.webview.html = this.getHistoryWebviewContent(history);
    }

    /**
     * Jump to a specific line in the editor
     */
    private jumpToLine(line: number): void {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return;
        }

        // Create a selection at the start of the target line
        const position = new vscode.Position(line, 0);
        editor.selection = new vscode.Selection(position, position);
        
        // Reveal the position in the editor
        editor.revealRange(
            new vscode.Range(position, position),
            vscode.TextEditorRevealType.InCenter
        );
    }

    /**
     * Request a fix for an issue
     */
    private requestFix(issue: CringeIssue): void {
        vscode.commands.executeCommand('code-cringe-detector.fixCringe', issue);
    }

    /**
     * Generate the HTML content for the webview
     */
    private getWebviewContent(issues: CringeIssue[]): string {
        const issueItems = issues.map(issue => `
            <div class="issue">
                <div class="issue-header">
                    <span class="issue-line">Line ${issue.line + 1}</span>
                    <span class="issue-type">${issue.issue}</span>
                </div>
                <div class="issue-snark">${issue.snark}</div>
                <div class="issue-actions">
                    <button class="action-button jump-button" data-line="${issue.line}">Jump to Line</button>
                    <button class="action-button fix-button" data-issue='${JSON.stringify(issue).replace(/'/g, "\\'")}'>Fix It</button>
                </div>
            </div>
        `).join('');

        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Code Cringe Detector</title>
            <style>
                body {
                    font-family: var(--vscode-font-family);
                    padding: 20px;
                    color: var(--vscode-foreground);
                }
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                }
                .title {
                    font-size: 1.2em;
                    font-weight: bold;
                }
                .history-button {
                    background-color: var(--vscode-button-background);
                    color: var(--vscode-button-foreground);
                    border: none;
                    padding: 6px 12px;
                    border-radius: 3px;
                    cursor: pointer;
                }
                .history-button:hover {
                    background-color: var(--vscode-button-hoverBackground);
                }
                .issue {
                    background-color: var(--vscode-editor-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 5px;
                    margin-bottom: 15px;
                    padding: 12px;
                }
                .issue-header {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 8px;
                }
                .issue-line {
                    font-weight: bold;
                    color: var(--vscode-editorLineNumber-foreground);
                }
                .issue-type {
                    color: var(--vscode-errorForeground);
                }
                .issue-snark {
                    margin-bottom: 10px;
                    font-style: italic;
                    color: var(--vscode-descriptionForeground);
                }
                .issue-actions {
                    display: flex;
                    gap: 10px;
                }
                .action-button {
                    background-color: var(--vscode-button-background);
                    color: var(--vscode-button-foreground);
                    border: none;
                    padding: 4px 8px;
                    border-radius: 3px;
                    cursor: pointer;
                }
                .action-button:hover {
                    background-color: var(--vscode-button-hoverBackground);
                }
                .empty-state {
                    text-align: center;
                    padding: 40px 20px;
                    color: var(--vscode-descriptionForeground);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="title">Code Cringe Detector</div>
                <button class="history-button" id="historyButton">View History</button>
            </div>
            
            ${issues.length > 0 
                ? `<div class="issues-container">${issueItems}</div>` 
                : `<div class="empty-state">
                    <p>No code cringe detected... yet.</p>
                    <p>Select some code and run "Detect Code Cringe" to analyze it.</p>
                  </div>`
            }
            
            <script>
                (function() {
                    // Handle jump to line
                    document.querySelectorAll('.jump-button').forEach(button => {
                        button.addEventListener('click', () => {
                            const line = parseInt(button.getAttribute('data-line'));
                            vscode.postMessage({
                                command: 'jumpToLine',
                                line: line
                            });
                        });
                    });
                    
                    // Handle fix issue
                    document.querySelectorAll('.fix-button').forEach(button => {
                        button.addEventListener('click', () => {
                            const issue = JSON.parse(button.getAttribute('data-issue'));
                            vscode.postMessage({
                                command: 'fixIssue',
                                issue: issue
                            });
                        });
                    });
                    
                    // Handle history button
                    document.getElementById('historyButton').addEventListener('click', () => {
                        vscode.postMessage({
                            command: 'showHistory'
                        });
                    });
                    
                    // Get access to the VS Code API
                    const vscode = acquireVsCodeApi();
                })();
            </script>
        </body>
        </html>`;
    }

    /**
     * Generate the HTML content for the history view
     */
    private getHistoryWebviewContent(history: any[]): string {
        const historyItems = history.map((item, index) => {
            const issueCount = item.issues.length;
            return `
                <div class="history-item">
                    <div class="history-header">
                        <span class="history-date">${formatTimestamp(item.timestamp)}</span>
                        <span class="history-count">${issueCount} issue${issueCount !== 1 ? 's' : ''}</span>
                    </div>
                    <div class="history-issues">
                        ${item.issues.map((issue: CringeIssue) => `
                            <div class="history-issue">
                                <span class="issue-line">Line ${issue.line + 1}:</span>
                                <span class="issue-text">${issue.issue}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }).join('');

        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Code Cringe History</title>
            <style>
                body {
                    font-family: var(--vscode-font-family);
                    padding: 20px;
                    color: var(--vscode-foreground);
                }
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                }
                .title {
                    font-size: 1.2em;
                    font-weight: bold;
                }
                .back-button {
                    background-color: var(--vscode-button-background);
                    color: var(--vscode-button-foreground);
                    border: none;
                    padding: 6px 12px;
                    border-radius: 3px;
                    cursor: pointer;
                }
                .back-button:hover {
                    background-color: var(--vscode-button-hoverBackground);
                }
                .history-item {
                    background-color: var(--vscode-editor-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 5px;
                    margin-bottom: 15px;
                    padding: 12px;
                }
                .history-header {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 8px;
                    padding-bottom: 8px;
                    border-bottom: 1px solid var(--vscode-panel-border);
                }
                .history-date {
                    font-weight: bold;
                }
                .history-count {
                    color: var(--vscode-descriptionForeground);
                }
                .history-issues {
                    display: flex;
                    flex-direction: column;
                    gap: 5px;
                }
                .history-issue {
                    display: flex;
                    gap: 10px;
                }
                .issue-line {
                    font-weight: bold;
                    color: var(--vscode-editorLineNumber-foreground);
                    min-width: 70px;
                }
                .issue-text {
                    color: var(--vscode-errorForeground);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="title">Code Cringe History</div>
                <button class="back-button" id="backButton">Back to Results</button>
            </div>
            
            <div class="history-container">
                ${historyItems}
            </div>
            
            <script>
                (function() {
                    // Handle back button
                    document.getElementById('backButton').addEventListener('click', () => {
                        vscode.postMessage({
                            command: 'backToResults'
                        });
                    });
                    
                    // Get access to the VS Code API
                    const vscode = acquireVsCodeApi();
                })();
            </script>
        </body>
        </html>`;
    }

    /**
     * Dispose of the panel
     */
    public dispose(): void {
        CringePanel.currentPanel = undefined;

        // Clean up resources
        this.panel.dispose();

        while (this.disposables.length) {
            const disposable = this.disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
