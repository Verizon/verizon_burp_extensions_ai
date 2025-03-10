#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

from burp import (
    IBurpExtender, ITab, IHttpListener, IContextMenuFactory,
    IContextMenuInvocation, IMessageEditorController
)
from java.io import PrintWriter
from javax.swing import (
    JPanel, JSplitPane, JTable, JScrollPane, JLabel, JButton,
    JOptionPane, BoxLayout, Box, SwingConstants, JTabbedPane,
    JTextArea, JComboBox, JDialog, SwingUtilities, JTextField
)
from javax.swing.table import AbstractTableModel
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Dimension
from java.awt.event import MouseAdapter, ActionListener
import json
import threading
import javax
import re

from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader


class TransactionTableModel(AbstractTableModel):
    def __init__(self, helpers):
        self._helpers = helpers
        self._transactions = []
        self._column_names = ["#", "Method", "URL", "Status", "Length"]

    def getColumnCount(self):
        return len(self._column_names)

    def getRowCount(self):
        return len(self._transactions)

    def getColumnName(self, col):
        return self._column_names[col]

    def getValueAt(self, row, col):
        if row < 0 or row >= len(self._transactions):
            return ""
        t = self._transactions[row]
        if col == 0:
            return row + 1
        elif col == 1:
            req_info = self._helpers.analyzeRequest(t)
            return req_info.getMethod()
        elif col == 2:
            req_info = self._helpers.analyzeRequest(t)
            return str(req_info.getUrl())
        elif col == 3:
            resp = t.getResponse()
            if resp:
                resp_info = self._helpers.analyzeResponse(resp)
                return resp_info.getStatusCode()
            else:
                return ""
        elif col == 4:
            resp = t.getResponse()
            if resp:
                return len(resp)
            else:
                return 0
        return ""

    def addTransaction(self, httpRequestResponse):
        self._transactions.append(httpRequestResponse)
        self.fireTableRowsInserted(len(self._transactions) - 1, len(self._transactions) - 1)

    def getTransaction(self, rowIndex):
        if 0 <= rowIndex < len(self._transactions):
            return self._transactions[rowIndex]
        return None

    def getAllTransactions(self):
        return self._transactions[:]


class RequestResponseController(IMessageEditorController):
    def __init__(self, helpers):
        self._currentMessage = None
        self._helpers = helpers

    def getHttpService(self):
        return self._currentMessage.getHttpService() if self._currentMessage else None

    def getRequest(self):
        return self._currentMessage.getRequest() if self._currentMessage else None

    def getResponse(self):
        return self._currentMessage.getResponse() if self._currentMessage else None

    def setMessage(self, message):
        self._currentMessage = message


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Bulk Analyze Transactions")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        self._allProviderModels = {
            "Azure": ["azure-gpt-3.5", "azure-gpt-4"],
            "OpenAI": ["gpt-3.5-turbo", "gpt-4"],
            "Ollama": ["ollama-7b", "ollama-phi4"],
            "GCP": ["gemini-2.0-flash-exp", "gemini-1.5-flash-002"]
        }
        self.fetchAllModels()

        self.chatHistory = []
        self.initUI()
        self.stdout.println("Bulk Analyze Transactions loaded.")

    def fetchAllModels(self):
        url_str = "http://localhost:8000/api/v1/bulk_analyze_http_transactions_endpoint/available_models"
        self.stdout.println("[fetchAllModels] => " + url_str)
        try:
            url = URL(url_str)
            conn = url.openConnection()
            conn.setRequestMethod("GET")
            code = conn.getResponseCode()
            self.stdout.println("[fetchAllModels] HTTP status=%d" % code)

            if 200 <= code < 300:
                inp = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                resp_str = ""
                line = inp.readLine()
                while line:
                    resp_str += line
                    line = inp.readLine()
                inp.close()
                data = json.loads(resp_str)
                providers_dict = data.get("providers", {})
                for p in ["Azure", "OpenAI", "Ollama", "GCP"]:
                    if p not in providers_dict:
                        providers_dict[p] = []
                self._allProviderModels = providers_dict
                self.stdout.println("[fetchAllModels] Successfully updated model list from backend.")
            else:
                self.stdout.println("[fetchAllModels] Non-2xx => fallback lists.")
        except Exception as e:
            self.stderr.println("[fetchAllModels] Exception => %s" % str(e))

    def initUI(self):
        self.mainPanel = JPanel(BorderLayout())
        self.mainPanel.setBorder(EmptyBorder(5, 5, 5, 5))

        titleLabel = JLabel("Bulk Analyze Transactions", SwingConstants.CENTER)
        titleLabel.setBorder(EmptyBorder(5, 0, 5, 0))
        self.mainPanel.add(titleLabel, BorderLayout.NORTH)

        self.modelPanel = JPanel()
        self.modelPanel.setLayout(BoxLayout(self.modelPanel, BoxLayout.X_AXIS))
        self.modelPanel.setBorder(EmptyBorder(5, 0, 5, 0))

        self.modelTypeLabel = JLabel("Model Provider:")
        self.modelTypeDropdown = JComboBox(["Azure", "OpenAI", "Ollama", "GCP"])
        self.modelTypeDropdown.addActionListener(self.onModelTypeChanged)

        self.modelNameLabel = JLabel("Model Name:")
        self.modelNameDropdown = JComboBox()
        self.populateModelNameDropdown("Azure")

        self.modelPanel.add(self.modelTypeLabel)
        self.modelPanel.add(self.modelTypeDropdown)
        self.modelPanel.add(self.modelNameLabel)
        self.modelPanel.add(self.modelNameDropdown)

        self.transaction_model = TransactionTableModel(self._helpers)
        self.transaction_table = JTable(self.transaction_model)
        scroll_table = JScrollPane(self.transaction_table)
        self.installRightClickMenuOnTable()

        self.controller = RequestResponseController(self._helpers)
        self.requestViewer = self._callbacks.createMessageEditor(self.controller, False)
        self.responseViewer = self._callbacks.createMessageEditor(self.controller, False)
        self.rr_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            self.requestViewer.getComponent(),
            self.responseViewer.getComponent()
        )
        self.rr_split.setResizeWeight(0.5)

        self.resultTabs = JTabbedPane()

        self.securityAnalysisArea = JTextArea()
        self.securityAnalysisArea.setEditable(False)
        self.resultTabs.addTab("Security Analysis", JScrollPane(self.securityAnalysisArea))

        self.detailedInsightsArea = JTextArea()
        self.detailedInsightsArea.setEditable(False)
        self.detailedInsightsArea.setLineWrap(True)
        self.detailedInsightsArea.setWrapStyleWord(True)
        self.resultTabs.addTab("Detailed Insights", JScrollPane(self.detailedInsightsArea))

        self.chatbotActivityArea = JTextArea()
        self.chatbotActivityArea.setEditable(False)
        self.resultTabs.addTab("Chatbot Activity", JScrollPane(self.chatbotActivityArea))

        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_table, self.rr_split)
        top_split.setResizeWeight(0.5)

        self.main_vertical_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, self.resultTabs)
        self.main_vertical_split.setResizeWeight(0.66)

        buttonPanel = JPanel()
        buttonPanel.setLayout(BoxLayout(buttonPanel, BoxLayout.X_AXIS))
        buttonPanel.setBorder(EmptyBorder(5, 0, 5, 0))

        self.runAnalysisButton = JButton("Run Security Analysis", actionPerformed=self.runSecurityAnalysis)
        self.summaryButton = JButton("Get Detailed Insights", actionPerformed=self.getDetailedInsights)
        self.chatbotButton = JButton("Find Chatbot Activity", actionPerformed=self.findChatbotActivity)
        self.clearButton = JButton("Clear Selected", actionPerformed=self.clearResults)

        buttonPanel.add(Box.createHorizontalGlue())
        buttonPanel.add(self.runAnalysisButton)
        buttonPanel.add(Box.createHorizontalStrut(5))
        buttonPanel.add(self.summaryButton)
        buttonPanel.add(Box.createHorizontalStrut(5))
        buttonPanel.add(self.chatbotButton)
        buttonPanel.add(Box.createHorizontalStrut(5))
        buttonPanel.add(self.clearButton)
        buttonPanel.add(Box.createHorizontalGlue())

        centerPanel = JPanel(BorderLayout())
        centerPanel.add(self.modelPanel, BorderLayout.NORTH)
        centerPanel.add(self.main_vertical_split, BorderLayout.CENTER)

        self.mainPanel.add(centerPanel, BorderLayout.CENTER)
        self.mainPanel.add(buttonPanel, BorderLayout.SOUTH)

        self.transaction_table.getSelectionModel().addListSelectionListener(
            lambda e: self.updateRequestResponseView()
        )

        self.chatPanel = self.createChatPanel()

        self.mainSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.mainPanel, self.chatPanel)
        self.mainSplitPane.setOneTouchExpandable(True)
        self.mainSplitPane.setResizeWeight(1.0)
        self.mainSplitPane.setDividerLocation(0.8)

        self._callbacks.addSuiteTab(self)

    def installRightClickMenuOnTable(self):
        table = self.transaction_table
        class TableMouseAdapter(MouseAdapter):
            def __init__(self, outer):
                self.outer = outer

            def maybeShowPopup(self, e):
                if e.isPopupTrigger():
                    popup = JPopupMenu()
                    row = table.rowAtPoint(e.getPoint())
                    if row != -1 and not table.getSelectionModel().isSelectedIndex(row):
                        table.setRowSelectionInterval(row, row)
                    selectedRows = table.getSelectedRows()
                    if len(selectedRows) == 0:
                        return

                    mRepeater = JMenuItem("Send to Repeater")
                    def doSendRepeater(ev):
                        for r in selectedRows:
                            msg = self.outer.transaction_model.getTransaction(r)
                            if msg:
                                reqStr = self.outer._helpers.bytesToString(msg.getRequest())
                                host, port, isSSL, reqBytes = self.outer.parseHostPortSslFromString(reqStr)
                                if host:
                                    self.outer._callbacks.sendToRepeater(host, port, isSSL, reqBytes, "Bulk Analyze Txns")
                    mRepeater.addActionListener(doSendRepeater)
                    popup.add(mRepeater)

                    mIntruder = JMenuItem("Send to Intruder")
                    def doSendIntruder(ev):
                        for r in selectedRows:
                            msg = self.outer.transaction_model.getTransaction(r)
                            if msg:
                                reqStr = self.outer._helpers.bytesToString(msg.getRequest())
                                host, port, isSSL, reqBytes = self.outer.parseHostPortSslFromString(reqStr)
                                if host:
                                    self.outer._callbacks.sendToIntruder(host, port, isSSL, reqBytes, None)
                    mIntruder.addActionListener(doSendIntruder)
                    popup.add(mIntruder)

                    mActiveScan = JMenuItem("Do Active Scan")
                    def doActiveScan(ev):
                        for r in selectedRows:
                            msg = self.outer.transaction_model.getTransaction(r)
                            if msg:
                                reqStr = self.outer._helpers.bytesToString(msg.getRequest())
                                host, port, isSSL, reqBytes = self.outer.parseHostPortSslFromString(reqStr)
                                if host:
                                    self.outer._callbacks.doActiveScan(host, port, isSSL, reqBytes)
                    mActiveScan.addActionListener(doActiveScan)
                    popup.add(mActiveScan)

                    mAddScope = JMenuItem("Add Host to Scope")
                    def doAddScope(ev):
                        for r in selectedRows:
                            msg = self.outer.transaction_model.getTransaction(r)
                            if msg:
                                reqStr = self.outer._helpers.bytesToString(msg.getRequest())
                                host, port, isSSL, reqBytes = self.outer.parseHostPortSslFromString(reqStr)
                                if host:
                                    proto = "https" if isSSL else "http"
                                    urlStr = "%s://%s:%d" % (proto, host, port)
                                    self.outer._callbacks.includeInScope(URL(urlStr))
                    mAddScope.addActionListener(doAddScope)
                    popup.add(mAddScope)

                    mExcludeScope = JMenuItem("Exclude Host from Scope")
                    def doExcludeScope(ev):
                        for r in selectedRows:
                            msg = self.outer.transaction_model.getTransaction(r)
                            if msg:
                                reqStr = self.outer._helpers.bytesToString(msg.getRequest())
                                host, port, isSSL, reqBytes = self.outer.parseHostPortSslFromString(reqStr)
                                if host:
                                    proto = "https" if isSSL else "http"
                                    urlStr = "%s://%s:%d" % (proto, host, port)
                                    self.outer._callbacks.excludeFromScope(URL(urlStr))
                    mExcludeScope.addActionListener(doExcludeScope)
                    popup.add(mExcludeScope)

                    popup.show(e.getComponent(), e.getX(), e.getY())

            def mousePressed(self, e):
                self.maybeShowPopup(e)

            def mouseReleased(self, e):
                self.maybeShowPopup(e)

        table.addMouseListener(TableMouseAdapter(self))

    def createChatPanel(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(5, 5, 5, 5))
        panel.setPreferredSize(Dimension(300, 600))

        topBar = JPanel()
        topBar.setLayout(BoxLayout(topBar, BoxLayout.X_AXIS))
        topLabel = JLabel("Model Chat", SwingConstants.LEFT)
        self.viewHistoryButton = JButton("History", actionPerformed=self.onViewHistoryClicked)
        topBar.add(topLabel)
        topBar.add(Box.createHorizontalGlue())
        topBar.add(self.viewHistoryButton)
        panel.add(topBar, BorderLayout.NORTH)

        # Plain text for chat display
        self.chatDisplayArea = JTextArea()
        self.chatDisplayArea.setEditable(False)
        self.chatDisplayArea.setLineWrap(True)
        self.chatDisplayArea.setWrapStyleWord(True)
        chatScroll = JScrollPane(self.chatDisplayArea)
        panel.add(chatScroll, BorderLayout.CENTER)

        bottomPanel = JPanel()
        bottomPanel.setLayout(BoxLayout(bottomPanel, BoxLayout.X_AXIS))

        self.chatPromptArea = JTextArea(3, 20)
        self.chatPromptArea.setLineWrap(True)
        self.chatPromptArea.setWrapStyleWord(True)
        promptScroll = JScrollPane(self.chatPromptArea)
        promptScroll.setPreferredSize(Dimension(200, 60))

        self.chatSendButton = JButton("Send", actionPerformed=self.onSendChat)
        self.chatClearWindowButton = JButton("Clear Chat Window", actionPerformed=self.onClearChatWindow)

        bottomPanel.add(promptScroll)
        bottomPanel.add(Box.createHorizontalStrut(5))
        bottomPanel.add(self.chatSendButton)
        bottomPanel.add(Box.createHorizontalStrut(5))
        bottomPanel.add(self.chatClearWindowButton)

        panel.add(bottomPanel, BorderLayout.SOUTH)
        return panel

    def onClearChatWindow(self, event):
        self.chatDisplayArea.setText("")
        JOptionPane.showMessageDialog(
            self.mainPanel,
            "Chat window cleared (history remains in memory)."
        )

    def onViewHistoryClicked(self, event):
        dialog = JDialog(SwingUtilities.getWindowAncestor(self.mainPanel), "Chat History", True)
        dialog.setSize(500, 400)
        dialog.setLocationRelativeTo(self.mainPanel)

        text = ""
        for idx, msg in enumerate(self.chatHistory):
            role = msg["role"]
            content = msg["content"]
            text += "{} {}:\n{}\n\n".format(role.capitalize(), idx+1, content)

        if not text.strip():
            text = "(No chat history yet)\n"

        historyArea = JTextArea()
        historyArea.setEditable(False)
        historyArea.setText(text)
        historyArea.setLineWrap(True)
        historyArea.setWrapStyleWord(True)
        scrollPane = JScrollPane(historyArea)
        dialog.add(scrollPane)
        dialog.setVisible(True)

    def onSendChat(self, event):
        prompt = self.chatPromptArea.getText().strip()
        if not prompt:
            return

        self.chatHistory.append({"role": "user", "content": prompt})
        self.chatDisplayArea.append("User: {}\n\n".format(prompt))
        self.chatPromptArea.setText("")

        selected_rows = self.transaction_table.getSelectedRows()
        selected_transactions = []
        for row in selected_rows:
            msg = self.transaction_model.getTransaction(row)
            req = msg.getRequest()
            resp = msg.getResponse()
            req_str = self._helpers.bytesToString(req) if req else "No request"
            resp_str = self._helpers.bytesToString(resp) if resp else "No response"
            table_index = row + 1
            selected_transactions.append({
                "table_index": table_index,
                "request": req_str,
                "response": resp_str
            })

        model_type_ui = self.modelTypeDropdown.getSelectedItem()
        if model_type_ui == "Azure":
            final_model_type = "AzureOpenAI"
        elif model_type_ui == "GCP":
            final_model_type = "GCP"
        else:
            final_model_type = model_type_ui

        model_id = self.modelNameDropdown.getSelectedItem()

        thread = threading.Thread(
            target=self.chatWorker,
            args=(prompt, selected_transactions, final_model_type, model_id)
        )
        thread.start()

    def chatWorker(self, userPrompt, selectedTxns, model_type, model_id):
        try:
            url_str = "http://localhost:8000/api/v1/bulk_analyze_http_transactions_endpoint/chat_with_gemini"
            headers = {"Content-Type": "application/json"}

            payload = {
                "model_type": model_type,
                "model_id": model_id,
                "conversation_history": self.chatHistory,
                "user_prompt": userPrompt,
                "selected_transactions": selectedTxns
            }
            json_data = json.dumps(payload)
            self.stdout.println("[chatWorker] POST => {}\nPayload:\n{}".format(url_str, json_data))

            url = URL(url_str)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", headers["Content-Type"])
            conn.setDoOutput(True)

            out_writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            out_writer.write(json_data)
            out_writer.flush()
            out_writer.close()

            code = conn.getResponseCode()
            self.stdout.println("[chatWorker] Response code: %d" % code)

            if 200 <= code < 300:
                inp = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                resp_str = ""
                line = inp.readLine()
                while line:
                    resp_str += line
                    line = inp.readLine()
                inp.close()

                self.stdout.println("[chatWorker] Raw response:\n" + resp_str)

                parsed = json.loads(resp_str)
                new_message = parsed.get("assistant_message", "")
                updated_history = parsed.get("conversation_history", [])

                self.chatHistory = updated_history
                self.chatDisplayArea.append("Model: {}\n\n".format(new_message))
            else:
                err = conn.getErrorStream()
                if err:
                    err_reader = BufferedReader(InputStreamReader(err, "UTF-8"))
                    err_resp = ""
                    line = err_reader.readLine()
                    while line:
                        err_resp += line
                        line = err_reader.readLine()
                    err_reader.close()
                    raise Exception("Backend error %d: %s" % (code, err_resp))
                else:
                    raise Exception("Backend returned code %d with no error stream" % code)
        except Exception as e:
            self.stderr.println("Error in chatWorker: " + str(e))
            JOptionPane.showMessageDialog(self.mainPanel, "Error in Chat: %s" % str(e))

    def onModelTypeChanged(self, event):
        selected_type = self.modelTypeDropdown.getSelectedItem()
        self.populateModelNameDropdown(selected_type)

    def populateModelNameDropdown(self, provider):
        self.modelNameDropdown.removeAllItems()
        if provider in self._allProviderModels:
            models = self._allProviderModels[provider]
        else:
            models = []
        if not models:
            models = ["(No models found)"]
        for m in models:
            self.modelNameDropdown.addItem(m)

    def getTabCaption(self):
        return "Bulk Analyze Transactions"

    def getUiComponent(self):
        return self.mainSplitPane

    def createMenuItems(self, invocation):
        menuItems = []
        menuItem = javax.swing.JMenuItem(
            "Send to Bulk Analyze Transactions",
            actionPerformed=lambda x: self.handleSendToExtension(invocation)
        )
        menuItems.append(menuItem)
        return menuItems

    def handleSendToExtension(self, invocation):
        selected = invocation.getSelectedMessages()
        if selected:
            for msg in selected:
                self.transaction_model.addTransaction(msg)
            JOptionPane.showMessageDialog(self.mainPanel, "Selected requests added. You can now run analysis.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass

    def runSecurityAnalysis(self, event):
        model_type_ui = self.modelTypeDropdown.getSelectedItem()
        if model_type_ui == "Azure":
            final_model_type = "AzureOpenAI"
        elif model_type_ui == "GCP":
            final_model_type = "GCP"
        else:
            final_model_type = model_type_ui

        model_id = self.modelNameDropdown.getSelectedItem()
        transactions = self.extractAllTransactions()
        if not transactions:
            JOptionPane.showMessageDialog(self.mainPanel, "No transactions available.")
            return

        t = threading.Thread(target=self.runSecurityAnalysisWorker, args=(transactions, final_model_type, model_id))
        t.start()

    def runSecurityAnalysisWorker(self, transactions, model_type, model_id):
        try:
            endpoint_name = "bulk_analyze_http_transactions_endpoint"
            noneVal, analysis_dict = self.sendToBackend(transactions, endpoint_name, model_type, model_id)
            formatted = self.formatSecurityAnalysis(analysis_dict)
            self.securityAnalysisArea.append("\n--- Security Analysis ---\n")
            self.securityAnalysisArea.append(formatted + "\n\n")
            JOptionPane.showMessageDialog(self.mainPanel, "Security Analysis complete.")
        except Exception as e:
            self.stderr.println("Error in runSecurityAnalysisWorker: " + str(e))
            JOptionPane.showMessageDialog(self.mainPanel, "Error in Security Analysis: " + str(e))

    def getDetailedInsights(self, event):
        model_type_ui = self.modelTypeDropdown.getSelectedItem()
        if model_type_ui == "Azure":
            final_model_type = "AzureOpenAI"
        elif model_type_ui == "GCP":
            final_model_type = "GCP"
        else:
            final_model_type = model_type_ui

        model_id = self.modelNameDropdown.getSelectedItem()
        transactions = self.extractAllTransactions()
        if not transactions:
            JOptionPane.showMessageDialog(self.mainPanel, "No transactions to summarize.")
            return

        t = threading.Thread(
            target=self.getDetailedInsightsWorker,
            args=(transactions, final_model_type, model_id)
        )
        t.start()

    def getDetailedInsightsWorker(self, transactions, model_type, model_id):
        try:
            endpoint_name = "bulk_analyze_http_transactions_endpoint/summary_http_requests_batch"
            result = self.sendToBackend(transactions, endpoint_name, model_type, model_id)
            if isinstance(result, tuple):
                result = result[0] if len(result) else {}

            summary_str = ""
            if isinstance(result, dict):
                summary_str = result.get("summary", "")
            else:
                summary_str = str(result)

            self.detailedInsightsArea.append("\n--- Detailed Insights ---\n")
            self.detailedInsightsArea.append(summary_str + "\n\n")
            JOptionPane.showMessageDialog(self.mainPanel, "Insights complete.")
        except Exception as e:
            self.stderr.println("Error in getDetailedInsightsWorker: " + str(e))
            JOptionPane.showMessageDialog(self.mainPanel, "Error in Detailed Insights: " + str(e))

    def findChatbotActivity(self, event):
        model_type_ui = self.modelTypeDropdown.getSelectedItem()
        if model_type_ui == "Azure":
            final_model_type = "AzureOpenAI"
        elif model_type_ui == "GCP":
            final_model_type = "GCP"
        else:
            final_model_type = model_type_ui

        model_id = self.modelNameDropdown.getSelectedItem()

        transactions = self.extractAllTransactions()
        if not transactions:
            JOptionPane.showMessageDialog(self.mainPanel, "No transactions to analyze.")
            return

        t = threading.Thread(
            target=self.findChatbotActivityWorker,
            args=(transactions, final_model_type, model_id)
        )
        t.start()

    def findChatbotActivityWorker(self, transactions, model_type, model_id):
        try:
            endpoint_name = "bulk_analyze_http_transactions_endpoint/find_chatbot_activity"
            result = self.sendToBackend(transactions, endpoint_name, model_type, model_id)
            formatted = self.formatChatbotActivity(result)
            self.chatbotActivityArea.append("\n--- Chatbot Activity ---\n")
            self.chatbotActivityArea.append(formatted + "\n\n")
            JOptionPane.showMessageDialog(self.mainPanel, "Chatbot activity detection complete.")
        except Exception as e:
            self.stderr.println("Error in findChatbotActivityWorker: " + str(e))
            JOptionPane.showMessageDialog(self.mainPanel, "Error in chatbot activity detection: " + str(e))

    def clearResults(self, event):
        selected_rows = self.transaction_table.getSelectedRows()
        if not selected_rows or len(selected_rows) == 0:
            JOptionPane.showMessageDialog(self.mainPanel, "No transactions selected to clear.")
            return

        for row in sorted(selected_rows, reverse=True):
            del self.transaction_model._transactions[row]
        self.transaction_model.fireTableDataChanged()
        self.transaction_table.clearSelection()
        self.transaction_table.repaint()
        self.controller.setMessage(None)
        self.requestViewer.setMessage(None, True)
        self.responseViewer.setMessage(None, False)
        self.updateRequestResponseView()
        self.stdout.println("Cleared selected transactions.")
        JOptionPane.showMessageDialog(self.mainPanel, "Selected transactions cleared.")

    def updateRequestResponseView(self):
        row = self.transaction_table.getSelectedRow()
        if row < 0:
            self.controller.setMessage(None)
            self.requestViewer.setMessage(None, True)
            self.responseViewer.setMessage(None, False)
            return

        msg = self.transaction_model.getTransaction(row)
        self.controller.setMessage(msg)
        self.requestViewer.setMessage(msg.getRequest(), True)
        self.responseViewer.setMessage(msg.getResponse(), False)

    def extractAllTransactions(self):
        transactions = []
        all_msgs = self.transaction_model.getAllTransactions()
        for idx, msg in enumerate(all_msgs):
            req = msg.getRequest()
            resp = msg.getResponse()
            req_str = self._helpers.bytesToString(req) if req else ""
            resp_str = self._helpers.bytesToString(resp) if resp else ""
            t_index = idx + 1
            transactions.append({
                "table_index": t_index,
                "request": req_str,
                "response": resp_str
            })
        return transactions

    def sendToBackend(self, transactions, endpoint_name, model_type, model_id):
        try:
            url_str = "http://localhost:8000/api/v1/" + endpoint_name + "/"
            payload = {
                "model_type": model_type,
                "model_id": model_id,
                "transactions": transactions
            }
            json_data = json.dumps(payload)
            self.stdout.println("[sendToBackend] POST => {}\nPayload:\n{}".format(url_str, json_data))

            url = URL(url_str)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setDoOutput(True)

            out_writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            out_writer.write(json_data)
            out_writer.flush()
            out_writer.close()

            code = conn.getResponseCode()
            self.stdout.println("[sendToBackend] Response code: %d" % code)

            if 200 <= code < 300:
                inp = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                resp_str = ""
                line = inp.readLine()
                while line:
                    resp_str += line
                    line = inp.readLine()
                inp.close()

                self.stdout.println("[sendToBackend] Raw response:\n" + resp_str)
                parsed = json.loads(resp_str)

                if endpoint_name == "bulk_analyze_http_transactions_endpoint":
                    return (None, parsed)
                return parsed
            else:
                err = conn.getErrorStream()
                if err:
                    err_reader = BufferedReader(InputStreamReader(err, "UTF-8"))
                    err_resp = ""
                    line = err_reader.readLine()
                    while line:
                        err_resp += line
                        line = err_reader.readLine()
                    err_reader.close()
                    raise Exception("Backend error %d: %s" % (code, err_resp))
                else:
                    raise Exception("Backend returned code %d with no error stream" % code)
        except Exception as e:
            raise Exception("sendToBackend => " + str(e))

    def formatSecurityAnalysis(self, analysis_dict):
        try:
            if not isinstance(analysis_dict, dict):
                return str(analysis_dict)
            arr = analysis_dict.get("TRANSACTION ANALYSIS", [])
            if not arr:
                return "No transactions analyzed."

            result = ""
            for entry in arr:
                req_num = entry.get("Request Number", "?")
                threat_level = entry.get("Threat Level", "?")
                det_threats = entry.get("Detected Threats", [])
                explanation = entry.get("Explanation", "")

                if not det_threats:
                    det_threats = ["None"]

                chunk = (
                    "Transaction #{}\nThreat Level: {}\n"
                    "Detected Threats: {}\nExplanation:\n{}\n"
                    "-----------------------------------------\n\n"
                ).format(req_num, threat_level, ", ".join(det_threats), explanation)
                result += chunk
            return result.strip()
        except:
            return str(analysis_dict)

    def formatChatbotActivity(self, result):
        if not isinstance(result, dict):
            return str(result)
        arr = result.get("transactions_with_chatbot_activity", [])
        if not arr:
            return "No chatbot activity found."

        out = ""
        for r in arr:
            tnum = r.get("transaction_number", "?")
            expl = r.get("explanation", "")
            chunk = (
                "Transaction #{}\nExplanation:\n{}\n"
                "-----------------------------------------\n\n"
            ).format(tnum, expl)
            out += chunk
        return out.strip()

    def parseHostPortSslFromString(self, requestString):
        lines = requestString.replace('\r\n', '\n').split('\n')
        if not lines:
            return (None, 0, False, self._helpers.stringToBytes(requestString))
        firstLineParts = lines[0].split()
        if len(firstLineParts) >= 3 and firstLineParts[-1].upper().strip() == "HTTP/2":
            firstLineParts[-1] = "HTTP/1.1"
            lines[0] = " ".join(firstLineParts)
        hostHeader = None
        for l in lines:
            if l.lower().startswith("host:"):
                hostHeader = l.strip()
                break
        if not hostHeader:
            return (None, 0, True, self._helpers.stringToBytes("\r\n".join(lines)))
        splitted = hostHeader.split(":", 1)
        if len(splitted) < 2:
            return (None, 0, True, self._helpers.stringToBytes("\r\n".join(lines)))
        realHostPart = splitted[1].strip()
        if ":" in realHostPart:
            hParts = realHostPart.split(":")
            host = hParts[0]
            try:
                port = int(hParts[1])
            except:
                port = 443
        else:
            host = realHostPart
            port = 443
        isSSL = True
        finalRequest = "\r\n".join(lines)
        return (host, port, isSSL, self._helpers.stringToBytes(finalRequest))
