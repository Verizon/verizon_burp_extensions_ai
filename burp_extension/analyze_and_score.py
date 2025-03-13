#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Analyze and Score
"""

from burp import (
    IBurpExtender, ITab,
    IHttpListener, IContextMenuFactory,
    IContextMenuInvocation
)
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import (
    JPanel, JTable, JTextArea, JScrollPane,
    BorderFactory, ListSelectionModel, JSplitPane, JLabel,
    JTabbedPane, JButton, JMenuItem, JFileChooser, JOptionPane,
    BoxLayout, Box, JComboBox, JPopupMenu, SwingUtilities
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.util import ArrayList
from java.lang import Thread, Runnable
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import base64

class BurpExtender(
    IBurpExtender, ITab, IHttpListener,
    IContextMenuFactory, ListSelectionListener, ActionListener
):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Analyze and Score")

        # Register ourselves for context menus & HTTP listening
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

        # Main panel
        self.mainPanel = JPanel(BorderLayout())
        headerPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        headerPanel.add(JLabel("Analyze and Score - Extended Benchmark Demo"))
        self.mainPanel.add(headerPanel, BorderLayout.NORTH)

        # Model selection row (Azure / OpenAI / Ollama / GCP)
        self.modelPanel = JPanel()
        self.modelPanel.setLayout(BoxLayout(self.modelPanel, BoxLayout.X_AXIS))

        self.modelProviderLabel = JLabel("Provider:")
        # ADDED GCP to the combo box
        self.modelProviderCombo = JComboBox(["Azure","OpenAI","Ollama","GCP"])

        self.modelNameLabel = JLabel("Model:")
        self.modelNameCombo = JComboBox()

        self.allProviderModels = {}
        self.fetchAllModelsFromBackend()

        # Default to "Azure"
        self.populateModelDropdown("Azure")

        def onProviderChange(e):
            which = self.modelProviderCombo.getSelectedItem()
            self.populateModelDropdown(which)
        self.modelProviderCombo.addActionListener(onProviderChange)

        self.modelPanel.add(self.modelProviderLabel)
        self.modelPanel.add(self.modelProviderCombo)
        self.modelPanel.add(self.modelNameLabel)
        self.modelPanel.add(self.modelNameCombo)
        self.mainPanel.add(self.modelPanel, BorderLayout.SOUTH)

        # Create a table for transactions
        self.tableModel = DefaultTableModel(["Index","Request","Response","Status"], 0)
        self.resultsTable = JTable(self.tableModel)
        self.resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.resultsTable.getSelectionModel().addListSelectionListener(self)

        scrollTable = JScrollPane(self.resultsTable)
        scrollTable.setBorder(BorderFactory.createTitledBorder("Transaction Table"))

        # Buttons row
        buttonRow = JPanel(FlowLayout(FlowLayout.LEFT))

        self.exportButton = JButton("Export Results")
        self.exportButton.setActionCommand("export_results")
        self.exportButton.addActionListener(self)
        buttonRow.add(self.exportButton)

        self.analyzeAllButton = JButton("Analyze All (Score+Category)")
        self.analyzeAllButton.setActionCommand("analyze_all")
        self.analyzeAllButton.addActionListener(self)
        buttonRow.add(self.analyzeAllButton)

        self.benchmarkButton = JButton("Benchmark")
        self.benchmarkButton.setActionCommand("benchmark")
        self.benchmarkButton.addActionListener(self)
        buttonRow.add(self.benchmarkButton)

        self.clearButton = JButton("Clear Selected")
        self.clearButton.setActionCommand("clear_selected")
        self.clearButton.addActionListener(self)
        buttonRow.add(self.clearButton)

        topPane = JPanel(BorderLayout())
        topPane.add(scrollTable, BorderLayout.CENTER)
        topPane.add(buttonRow, BorderLayout.NORTH)

        # Request/Response text areas
        self.requestText = JTextArea(10,40)
        requestScroll = JScrollPane(self.requestText)
        requestScroll.setBorder(BorderFactory.createTitledBorder("Request Details"))

        resendBut = JButton("Resend")
        resendBut.setActionCommand("resend_request")
        resendBut.addActionListener(self)
        topReqPanel = JPanel(BorderLayout())
        topReqPanel.add(resendBut, BorderLayout.EAST)

        leftReqPanel = JPanel(BorderLayout())
        leftReqPanel.add(requestScroll, BorderLayout.CENTER)
        leftReqPanel.add(topReqPanel, BorderLayout.NORTH)

        self.responseText = JTextArea(10,40)
        self.responseText.setEditable(False)
        respScroll = JScrollPane(self.responseText)
        respScroll.setBorder(BorderFactory.createTitledBorder("Response Details"))

        reqRespSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, leftReqPanel, respScroll)
        reqRespSplit.setResizeWeight(0.5)

        leftSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, topPane, reqRespSplit)
        leftSplit.setResizeWeight(0.3)
        leftSplit.setDividerLocation(300)

        # Tabbed output
        self.tabbedPane = JTabbedPane()

        # Main analysis
        mainAnalysisPanel = JPanel(BorderLayout())
        self.analyzeButton = JButton("Analyze Request/Response Pair")
        self.analyzeButton.setActionCommand("analyze_client_request")
        self.analyzeButton.addActionListener(self)
        mainAnalysisPanel.add(self.analyzeButton, BorderLayout.NORTH)

        self.llmOutput = JTextArea(10,20)
        self.llmOutput.setEditable(False)
        self.llmOutput.setLineWrap(True)
        self.llmOutput.setWrapStyleWord(True)
        scrA = JScrollPane(self.llmOutput)
        scrA.setBorder(BorderFactory.createTitledBorder("Analysis Output"))
        mainAnalysisPanel.add(scrA, BorderLayout.CENTER)

        self.tabbedPane.addTab("Main Analysis", mainAnalysisPanel)

        # Option-based endpoints
        self.option_text_map = {
            "analyze_get_params":"Suggest GET Parameters",
            "analyze_post_params":"Suggest POST Parameters",
            "find_endpoints":"Suggest Endpoints",
            "check_headers":"Suggest Headers",
            "review_server_response":"Analyze Server Response"
        }

        for key,label in self.option_text_map.items():
            p = JPanel(BorderLayout())
            b = JButton(label)
            b.setActionCommand("option_"+key)
            b.addActionListener(self)
            p.add(b, BorderLayout.NORTH)

            outArea = JTextArea(10,40)
            outArea.setEditable(False)
            outArea.setLineWrap(True)
            outArea.setWrapStyleWord(True)
            sPane = JScrollPane(outArea)
            sPane.setBorder(BorderFactory.createTitledBorder(label+" Output"))
            p.add(sPane, BorderLayout.CENTER)
            setattr(self, key+"_output", outArea)

            self.tabbedPane.addTab(label, p)

        # Benchmark tab
        self.benchPanel = JPanel(BorderLayout())
        self.benchRun = JButton("Run Benchmark")
        self.benchRun.setActionCommand("run_benchmark")
        self.benchRun.addActionListener(self)
        self.benchPanel.add(self.benchRun, BorderLayout.NORTH)

        self.benchText = JTextArea(10,40)
        self.benchText.setEditable(False)
        self.benchText.setLineWrap(True)
        self.benchText.setWrapStyleWord(True)
        sp2 = JScrollPane(self.benchText)
        sp2.setBorder(BorderFactory.createTitledBorder("Benchmark Stats (Extended)"))
        self.benchPanel.add(sp2, BorderLayout.CENTER)

        self.tabbedPane.addTab("Benchmarking", self.benchPanel)

        rightPanel = JPanel(BorderLayout())
        rightPanel.add(self.tabbedPane, BorderLayout.CENTER)

        mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, rightPanel)
        mainSplit.setResizeWeight(0.7)
        mainSplit.setDividerLocation(800)

        self.mainPanel.add(mainSplit, BorderLayout.CENTER)

        # Spinner label
        self.statusLabel = JLabel("")
        statusPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        statusPanel.add(self.statusLabel)
        self.mainPanel.add(statusPanel, BorderLayout.NORTH)

        self.messageInfos = {}
        self._callbacks.addSuiteTab(self)

        self.installRightClickMenuOnTable()
        print("[AnalyzeScore Extended] Initialized with spinner + extended benchmark.")

    # -- processHttpMessage --
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass

    # -- getTabCaption / getUiComponent --
    def getTabCaption(self):
        return "Analyze and Score"

    def getUiComponent(self):
        return self.mainPanel

    # -- Spinner show/hide --
    def showSpinner(self, text="Processing..."):
        def doSet():
            self.statusLabel.setText(text)
        SwingUtilities.invokeLater(doSet)

    def hideSpinner(self):
        def doClear():
            self.statusLabel.setText("")
        SwingUtilities.invokeLater(doClear)

    # ----------------------------------------------------
    # fetchAllModelsFromBackend => environment-based
    # ----------------------------------------------------
    def fetchAllModelsFromBackend(self):
        # Fallback now includes "GCP" for user selection
        fallback = {
            "Azure": ["azure-gpt-3.5","azure-gpt-4"],
            "OpenAI": ["gpt-3.5-turbo","gpt-4"],
            "Ollama": ["ollama-7b","ollama-phi4"],
            "GCP": ["gemini-2.0-flash-exp","gemini-1.5-flash-002"]
        }
        try:
            urlStr = "http://localhost:8000/api/v1/analyze_and_score_endpoint/available_models"
            print("[fetchAllModelsFromBackend] =>", urlStr)
            conn = URL(urlStr).openConnection()
            conn.setRequestMethod("GET")
            code = conn.getResponseCode()
            print("[fetchAllModelsFromBackend] code=", code)

            if 200 <= code < 300:
                br = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                raw = ""
                line = br.readLine()
                while line:
                    raw += line
                    line = br.readLine()
                br.close()
                data = json.loads(raw)
                providers_dict = data.get("providers", {})
                print("[fetchAllModelsFromBackend] providers =>", providers_dict)
                if not providers_dict:
                    providers_dict = fallback
                self.allProviderModels = providers_dict
            else:
                print("[fetchAllModelsFromBackend] non-2xx => fallback")
                self.allProviderModels = fallback
        except Exception as e:
            print("[fetchAllModelsFromBackend] exception =>", str(e))
            self.allProviderModels = fallback

    def populateModelDropdown(self, provider):
        self.modelNameCombo.removeAllItems()
        if not self.allProviderModels:
            # fallback if no data
            self.allProviderModels = {
                "Azure": ["azure-gpt-3.5","azure-gpt-4"],
                "OpenAI": ["gpt-3.5-turbo","gpt-4"],
                "Ollama": ["ollama-7b","ollama-phi4"],
                "GCP": ["gemini-2.0-flash-exp","gemini-1.5-flash-002"]
            }

        modelList = self.allProviderModels.get(provider, [])
        if not modelList:
            modelList = ["NoModelsFound"]

        for m in modelList:
            self.modelNameCombo.addItem(m)

    # -- createMenuItems
    def createMenuItems(self, invocation):
        menu = ArrayList()
        selected = invocation.getSelectedMessages()
        if selected:
            mIt = JMenuItem("Send to Analyze and Score", actionPerformed=lambda x: self.handleAddToTable(selected))
            menu.add(mIt)
        return menu

    def handleAddToTable(self, msgs):
        for mInfo in msgs:
            req = mInfo.getRequest()
            resp = mInfo.getResponse()
            idx = self.tableModel.getRowCount()

            if req:
                anReq = self._helpers.analyzeRequest(req)
                heads = anReq.getHeaders()
                bdy = self._helpers.bytesToString(req[anReq.getBodyOffset():])
                if heads:
                    line0 = heads[0]
                else:
                    line0 = "(No request line)"
                reqSum = "%s (Payload len=%d)" % (line0, len(bdy))
            else:
                reqSum = "No Request"

            if resp:
                anResp = self._helpers.analyzeResponse(resp)
                sc = str(anResp.getStatusCode())
                rBody = self._helpers.bytesToString(resp[anResp.getBodyOffset():])
                respSum = rBody[:100]
            else:
                sc = "N/A"
                respSum = "No Response"

            self.tableModel.addRow([idx, reqSum, respSum, sc])
            self.messageInfos[idx] = {
                "request": self._helpers.bytesToString(req) if req else "",
                "response": self._helpers.bytesToString(resp) if resp else ""
            }

    # -- installRightClickMenuOnTable
    def installRightClickMenuOnTable(self):
        table = self.resultsTable
        class TableMouseAdapter(MouseAdapter):
            def __init__(self, ext):
                self.ext = ext
            def checkPopup(self, e):
                if e.isPopupTrigger():
                    popup = JPopupMenu()
                    row = table.rowAtPoint(e.getPoint())
                    if row != -1 and not table.isRowSelected(row):
                        table.setRowSelectionInterval(row, row)
                    selRows = table.getSelectedRows()
                    if len(selRows) == 0:
                        return

                    mRep = JMenuItem("Send to Repeater")
                    def doRep(ev):
                        for r in selRows:
                            reqS = self.ext.messageInfos[r]["request"]
                            host,port,isSSL,reqB = self.ext.parseHostPortSslFromString(reqS)
                            if host:
                                self.ext._callbacks.sendToRepeater(host,port,isSSL,reqB,"Analyze and Score")
                    mRep.addActionListener(doRep)
                    popup.add(mRep)

                    mIntr = JMenuItem("Send to Intruder")
                    def doIntr(ev):
                        for r in selRows:
                            reqS = self.ext.messageInfos[r]["request"]
                            host,port,isSSL,reqB = self.ext.parseHostPortSslFromString(reqS)
                            if host:
                                self.ext._callbacks.sendToIntruder(host,port,isSSL,reqB,None)
                    mIntr.addActionListener(doIntr)
                    popup.add(mIntr)

                    mAct = JMenuItem("Do Active Scan")
                    def doAct(ev):
                        for r in selRows:
                            reqS = self.ext.messageInfos[r]["request"]
                            host,port,isSSL,reqB = self.ext.parseHostPortSslFromString(reqS)
                            if host:
                                self.ext._callbacks.doActiveScan(host,port,isSSL,reqB)
                    mAct.addActionListener(doAct)
                    popup.add(mAct)

                    mAdd = JMenuItem("Add Host to Scope")
                    def doAdd(ev):
                        for r in selRows:
                            reqS = self.ext.messageInfos[r]["request"]
                            host,port,isSSL,_=self.ext.parseHostPortSslFromString(reqS)
                            if host:
                                proto="https" if isSSL else "http"
                                urlStr="%s://%s:%d"%(proto,host,port)
                                self.ext._callbacks.includeInScope(URL(urlStr))
                    mAdd.addActionListener(doAdd)
                    popup.add(mAdd)

                    mExcl = JMenuItem("Exclude Host from Scope")
                    def doExcl(ev):
                        for r in selRows:
                            reqS = self.ext.messageInfos[r]["request"]
                            host,port,isSSL,_=self.ext.parseHostPortSslFromString(reqS)
                            if host:
                                proto="https" if isSSL else "http"
                                urlStr="%s://%s:%d"%(proto,host,port)
                                self.ext._callbacks.excludeFromScope(URL(urlStr))
                    mExcl.addActionListener(doExcl)
                    popup.add(mExcl)

                    popup.show(e.getComponent(), e.getX(), e.getY())

            def mousePressed(self,e):
                self.checkPopup(e)
            def mouseReleased(self,e):
                self.checkPopup(e)

        table.addMouseListener(TableMouseAdapter(self))

    # -- parseHostPortSslFromString
    def parseHostPortSslFromString(self, requestString):
        lines = requestString.replace('\r\n','\n').split('\n')
        if not lines:
            return (None,0,False,self._helpers.stringToBytes(requestString))

        firstLine=lines[0].split()
        if len(firstLine)>=3 and firstLine[-1].upper().strip()=="HTTP/2":
            firstLine[-1]="HTTP/1.1"
            lines[0]=" ".join(firstLine)

        hostHeader=None
        for l in lines:
            if l.lower().startswith("host:"):
                hostHeader=l.strip()
                break
        if not hostHeader:
            return (None,0,True,self._helpers.stringToBytes("\r\n".join(lines)))

        splitted=hostHeader.split(":",1)
        if len(splitted)<2:
            return (None,0,True,self._helpers.stringToBytes("\r\n".join(lines)))

        realPart=splitted[1].strip()
        if ":" in realPart:
            hParts=realPart.split(":")
            host=hParts[0]
            try:
                port=int(hParts[1])
            except:
                port=443
        else:
            host=realPart
            port=443

        isSSL=True
        finalReq="\r\n".join(lines)
        return (host,port,isSSL,self._helpers.stringToBytes(finalReq))

    # -- Table row selection => show request/response
    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            row=self.resultsTable.getSelectedRow()
            if row>=0:
                info=self.messageInfos.get(row)
                if info:
                    self.requestText.setText(info["request"])
                    self.requestText.setCaretPosition(0)
                    self.responseText.setText(info["response"])
                    self.responseText.setCaretPosition(0)

    # -- ActionListener => handle each button
    def actionPerformed(self, evt):
        cmd=evt.getActionCommand()
        if cmd.startswith("option_"):
            opKey=cmd.replace("option_","")
            self.showSpinner("Analyzing option: %s..."%opKey)
            def worker():
                try:
                    self.doRunOptionAnalysis(opKey)
                finally:
                    self.hideSpinner()
            Thread(PyRunnable(worker)).start()

        elif cmd=="analyze_client_request":
            self.showSpinner("Analyzing request/response pair...")
            def worker():
                try:
                    self.doRunLLMAnalysis()
                finally:
                    self.hideSpinner()
            Thread(PyRunnable(worker)).start()

        elif cmd=="analyze_all":
            self.showSpinner("Analyzing all (Score+Category)...")
            def worker():
                try:
                    self.doRunAnalyzeAll()
                finally:
                    self.hideSpinner()
            Thread(PyRunnable(worker)).start()

        elif cmd=="benchmark" or cmd=="run_benchmark":
            self.showSpinner("Benchmark in progress...")
            def worker():
                try:
                    self.doRunBenchmark()
                finally:
                    self.hideSpinner()
            Thread(PyRunnable(worker)).start()

        elif cmd=="export_results":
            self.exportResults()

        elif cmd=="resend_request":
            self.showSpinner("Resending request...")
            def worker():
                try:
                    self.doResendRequest()
                finally:
                    self.hideSpinner()
            Thread(PyRunnable(worker)).start()

        elif cmd=="clear_selected":
            self.clearSelectedRows()

    # doRunOptionAnalysis
    def doRunOptionAnalysis(self, key):
        row=self.resultsTable.getSelectedRow()
        outA=getattr(self, key+"_output", None)
        if row<0:
            if outA:
                outA.setText("No row selected.")
            return

        msg=self.messageInfos.get(row)
        if not msg:
            if outA:
                outA.setText("No data found for row.")
            return

        req=msg["request"]
        resp=msg["response"]
        print("[doRunOptionAnalysis] row=%d, request len=%d, response len=%d" % (
            row, len(req), len(resp)
        ))

        # Decide final model_type for the backend call
        provider_ui=self.modelProviderCombo.getSelectedItem()
        if provider_ui=="Azure":
            final_model_type="AzureOpenAI"
        elif provider_ui=="GCP":
            final_model_type="GCP"
        else:
            final_model_type=provider_ui  # "OpenAI" or "Ollama"

        model_id=self.modelNameCombo.getSelectedItem()

        payload={
            "model_type": final_model_type,
            "model_id": model_id,
            "option_key": key,
            "request_text": self.redactSensitive(req),
            "response_text": resp
        }
        print("[doRunOptionAnalysis] sending JSON =>", json.dumps(payload))

        try:
            url=URL("http://localhost:8000/api/v1/analyze_and_score_endpoint/option_analyze")
            conn=url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type","application/json")
            conn.setRequestProperty("Accept","application/json")

            outS=OutputStreamWriter(conn.getOutputStream(),"UTF-8")
            outS.write(json.dumps(payload))
            outS.flush()
            outS.close()

            code=conn.getResponseCode()
            print("[doRunOptionAnalysis] HTTP code =>", code)
            if 200<=code<300:
                br=BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                r=""
                line=br.readLine()
                while line:
                    r+=line+"\n"
                    line=br.readLine()
                br.close()
                print("[doRunOptionAnalysis] raw response =>\n",r)
                parsed=json.loads(r)
                an=parsed.get("analysis","No analysis.")
                if outA:
                    outA.setText(an)
                    outA.setCaretPosition(0)
            else:
                eBr=BufferedReader(InputStreamReader(conn.getErrorStream(),"UTF-8"))
                errResp=""
                line=eBr.readLine()
                while line:
                    errResp+=line+"\n"
                    line=eBr.readLine()
                eBr.close()
                print("[doRunOptionAnalysis] server error =>\n",errResp)
                if outA:
                    outA.setText("Error from server:\n"+errResp)
        except Exception as e:
            print("[doRunOptionAnalysis] exception =>", e)
            if outA:
                outA.setText("Error: "+str(e))

    # doRunLLMAnalysis => "Analyze Request/Response Pair"
    def doRunLLMAnalysis(self):
        row = self.resultsTable.getSelectedRow()
        if row < 0:
            self.llmOutput.setText("No row selected.")
            return
        msg = self.messageInfos.get(row)
        if not msg:
            self.llmOutput.setText("No data found.")
            return

        req = msg["request"]
        resp = msg["response"]
        print("[doRunLLMAnalysis] row=%d, req len=%d, resp len=%d" % (row, len(req), len(resp)))

        provider_ui = self.modelProviderCombo.getSelectedItem()
        if provider_ui == "Azure":
            final_model_type = "AzureOpenAI"
        elif provider_ui == "GCP":
            final_model_type = "GCP"
        else:
            final_model_type = provider_ui

        model_id = self.modelNameCombo.getSelectedItem()

        payload = {
            "model_type": final_model_type,
            "model_id": model_id,
            "string_one": req,
            "string_two": resp
        }
        print("[doRunLLMAnalysis] JSON =>", json.dumps(payload))

        try:
            url = URL("http://localhost:8000/api/v1/analyze_and_score_endpoint/analyze_http_transaction")
            conn = url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")

            outS = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            outS.write(json.dumps(payload))
            outS.flush()
            outS.close()

            code = conn.getResponseCode()
            print("[doRunLLMAnalysis] code =>", code)
            if 200 <= code < 300:
                br = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                raw = ""
                line = br.readLine()
                while line:
                    raw += line + "\n"
                    line = br.readLine()
                br.close()
                print("[doRunLLMAnalysis] raw =>\n", raw)

                p = json.loads(raw)
                analysis = p.get("analysis", "No analysis.")
                if isinstance(analysis, dict) or isinstance(analysis, list):
                    analysis = json.dumps(analysis, indent=2)
                self.llmOutput.setText(analysis)
            else:
                eBr = BufferedReader(InputStreamReader(conn.getErrorStream(), "UTF-8"))
                err = ""
                line = eBr.readLine()
                while line:
                    err += line + "\n"
                    line = eBr.readLine()
                eBr.close()
                self.llmOutput.setText("Error:\n" + err)
        except Exception as e:
            print("[doRunLLMAnalysis] exception =>", e)
            self.llmOutput.setText("Error:\n" + str(e))

    # doRunAnalyzeAll => "Analyze All" Score+Category
    def doRunAnalyzeAll(self):
        colNames=[]
        for i in range(self.tableModel.getColumnCount()):
            colNames.append(self.tableModel.getColumnName(i))
        if "Score" not in colNames:
            self.tableModel.addColumn("Score")
            colNames.append("Score")
        if "Category" not in colNames:
            self.tableModel.addColumn("Category")
            colNames.append("Category")

        data=[]
        for r in range(self.tableModel.getRowCount()):
            msg=self.messageInfos.get(r)
            if msg:
                data.append({
                    "request": msg.get("request",""),
                    "response": msg.get("response",""),
                    "score":None,
                    "category":None
                })
            else:
                data.append({"request":"","response":"","score":None,"category":None})

        provider_ui=self.modelProviderCombo.getSelectedItem()
        if provider_ui=="Azure":
            final_model_type="AzureOpenAI"
        elif provider_ui=="GCP":
            final_model_type="GCP"
        else:
            final_model_type=provider_ui

        model_id=self.modelNameCombo.getSelectedItem()

        payload={
            "model_type": final_model_type,
            "model_id": model_id,
            "data": data
        }
        print("[doRunAnalyzeAll] JSON =>", json.dumps(payload))

        try:
            url=URL("http://localhost:8000/api/v1/analyze_and_score_endpoint/bulk_analysis")
            conn=url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type","application/json")
            conn.setRequestProperty("Accept","application/json")

            outS=OutputStreamWriter(conn.getOutputStream(),"UTF-8")
            outS.write(json.dumps(payload))
            outS.flush()
            outS.close()

            code=conn.getResponseCode()
            print("[doRunAnalyzeAll] code =>", code)
            if 200<=code<300:
                br=BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                raw=""
                line=br.readLine()
                while line:
                    raw+=line+"\n"
                    line=br.readLine()
                br.close()
                print("[doRunAnalyzeAll] raw =>\n",raw)
                respJ=json.loads(raw)
                scs=respJ.get("scores",[])
                cats=respJ.get("categories",[])
                sIdx=colNames.index("Score")
                cIdx=colNames.index("Category")

                for i in range(len(scs)):
                    self.tableModel.setValueAt(scs[i], i, sIdx)
                    self.tableModel.setValueAt(cats[i], i, cIdx)

                JOptionPane.showMessageDialog(self.mainPanel,"All items analyzed (Score+Category).")
            else:
                eBr=BufferedReader(InputStreamReader(conn.getErrorStream(),"UTF-8"))
                errTxt=""
                line=eBr.readLine()
                while line:
                    errTxt+=line+"\n"
                    line=eBr.readLine()
                eBr.close()
                print("[doRunAnalyzeAll] server error =>\n",errTxt)
                JOptionPane.showMessageDialog(self.mainPanel,"Error from bulk_analysis:\n"+errTxt,
                                              "Error",JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            print("[doRunAnalyzeAll] exception =>", e)
            JOptionPane.showMessageDialog(self.mainPanel,"Error in runAnalyzeAll:\n"+str(e),
                                          "Error",JOptionPane.ERROR_MESSAGE)

    #
    # doRunBenchmark => "Benchmark" with extended fields
    #
    def doRunBenchmark(self):
        colNames=[]
        for i in range(self.tableModel.getColumnCount()):
            colNames.append(self.tableModel.getColumnName(i))
        headers=colNames

        rows=[]
        for r in range(self.tableModel.getRowCount()):
            rowData=[]
            for c in range(self.tableModel.getColumnCount()):
                val=self.tableModel.getValueAt(r,c)
                if val is None:
                    val=u""
                if not isinstance(val,unicode):
                    try:
                        val=unicode(str(val),"utf-8","replace")
                    except:
                        val=unicode(val)
                rowData.append(val)
            rows.append(rowData)

        provider_ui=self.modelProviderCombo.getSelectedItem()
        if provider_ui=="Azure":
            final_model_type="AzureOpenAI"
        elif provider_ui=="GCP":
            final_model_type="GCP"
        else:
            final_model_type=provider_ui

        model_id=self.modelNameCombo.getSelectedItem()

        payload={
            "model_type": final_model_type,
            "model_id": model_id,
            "headers": headers,
            "rows": rows
        }
        print("[doRunBenchmark] JSON =>",json.dumps(payload))
        try:
            url=URL("http://localhost:8000/api/v1/analyze_and_score_endpoint/benchmark")
            conn=url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type","application/json")
            conn.setRequestProperty("Accept","application/json")

            outS=OutputStreamWriter(conn.getOutputStream(),"UTF-8")
            outS.write(json.dumps(payload))
            outS.flush()
            outS.close()

            code=conn.getResponseCode()
            print("[doRunBenchmark] code =>", code)
            if 200<=code<300:
                br=BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                raw=""
                line=br.readLine()
                while line:
                    raw+=line+"\n"
                    line=br.readLine()
                br.close()
                print("[doRunBenchmark] raw =>\n",raw)

                j=json.loads(raw)
                asciiTxt=self.formatBenchmarkResults(j)
                self.benchText.setText(asciiTxt)
                self.benchText.setCaretPosition(0)
                JOptionPane.showMessageDialog(self.mainPanel,"Benchmark complete.")
            else:
                eBr=BufferedReader(InputStreamReader(conn.getErrorStream(),"UTF-8"))
                errR=""
                line=eBr.readLine()
                while line:
                    errR+=line+"\n"
                    line=eBr.readLine()
                eBr.close()
                print("[doRunBenchmark] server error =>\n",errR)
                JOptionPane.showMessageDialog(self.mainPanel,"Error from benchmark:\n"+errR,
                                              "Error",JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            print("[doRunBenchmark] exception =>", e)
            JOptionPane.showMessageDialog(self.mainPanel,"Benchmark call error:\n"+str(e),
                                          "Error",JOptionPane.ERROR_MESSAGE)

    #
    # formatBenchmarkResults => with additional stats
    #
    def formatBenchmarkResults(self, j):
        lines=[]
        lines.append("=== [Benchmark Results] =======================")
        lines.append("Total Requests: %s" % j.get("total_requests","0"))
        lines.append("Need Review...: %s" % j.get("total_that_need_review","0"))
        lines.append("Fail %%.......: %.2f" % j.get("fail_percentage",0.0))
        lines.append("Avg Req Len...: %.2f" % j.get("average_request_length",0.0))
        lines.append("Longest Req...: %s" % j.get("longest_request","N/A"))
        lines.append("Shortest Req..: %s" % j.get("shortest_request","N/A"))
        lines.append("Avg Resp Len..: %.2f" % j.get("average_response_length",0.0))
        lines.append("Longest Resp..: %s" % j.get("longest_response","N/A"))
        lines.append("Shortest Resp.: %s" % j.get("shortest_response","N/A"))
        lines.append("Redirect Count: %s" % j.get("redirect_count","0"))
        lines.append("")
        lines.append("-- Status Code Distribution --")
        scd=j.get("status_code_distribution",{})
        for k,v in scd.items():
            lines.append("   %s => %s"%(k,v))
        lines.append("")
        lines.append("-- Method Distribution --")
        md=j.get("method_distribution",{})
        for k,v in md.items():
            lines.append("   %s => %s"%(k,v))
        lines.append("")
        lines.append("-- Category Stats --")
        cat=j.get("category_stats",{})
        for catName,catVal in cat.items():
            cCount=catVal.get("count",0)
            cFail=catVal.get("fail_count",0)
            cPct=catVal.get("fail_percentage",0.0)
            lines.append("   %s => count=%d, fail_count=%d, fail_pct=%.2f"%
                         (catName,cCount,cFail,cPct))
        lines.append("")
        lines.append("-- Server Distribution --")
        srvD=j.get("server_distribution",{})
        for sName,sCount in srvD.items():
            lines.append("   %s => %d"%(sName,sCount))
        lines.append("")
        lines.append("-- Content-Type Distribution --")
        ctd=j.get("content_type_distribution",{})
        for ctName,ctCount in ctd.items():
            lines.append("   %s => %d"%(ctName,ctCount))
        lines.append("==============================================")
        return "\n".join(lines)

    #
    # exportResults => "Export"
    #
    def exportResults(self):
        fmts=["csv","excel","parquet"]
        choice=JOptionPane.showInputDialog(
            self.mainPanel,"Choose export format:","Export Format",
            JOptionPane.PLAIN_MESSAGE,None,fmts,fmts[0]
        )
        if choice is None:
            return

        colNames=[]
        for i in range(self.tableModel.getColumnCount()):
            colNames.append(self.tableModel.getColumnName(i))

        rows=[]
        for r in range(self.tableModel.getRowCount()):
            rowData=[]
            for c in range(self.tableModel.getColumnCount()):
                val=self.tableModel.getValueAt(r,c)
                if val is None:
                    val=u""
                if not isinstance(val,unicode):
                    try:
                        val=unicode(str(val),"utf-8","replace")
                    except:
                        val=unicode(val)
                rowData.append(val)
            rows.append(rowData)

        payload={
            "headers": colNames,
            "rows": rows,
            "format": choice
        }
        print("[exportResults] JSON =>", json.dumps(payload))

        try:
            url=URL("http://localhost:8000/api/v1/analyze_and_score_endpoint/export")
            conn=url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestProperty("Content-Type","application/json")
            conn.setRequestProperty("Accept","application/json")

            outS=OutputStreamWriter(conn.getOutputStream(),"UTF-8")
            outS.write(json.dumps(payload))
            outS.flush()
            outS.close()

            code=conn.getResponseCode()
            print("[exportResults] code =>", code)
            if 200<=code<300:
                br=BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                rS=""
                line=br.readLine()
                while line:
                    rS+=line
                    line=br.readLine()
                br.close()

                j=json.loads(rS)
                b64=j.get("file_content_base64","")
                if not b64:
                    JOptionPane.showMessageDialog(self.mainPanel,
                                                  "No file content returned.",
                                                  "Error",
                                                  JOptionPane.ERROR_MESSAGE)
                    return
                fBytes=base64.b64decode(b64)
                fc=JFileChooser()
                fc.setDialogTitle("Save Results")
                if fc.showSaveDialog(self.mainPanel)==JFileChooser.APPROVE_OPTION:
                    path=fc.getSelectedFile().getAbsolutePath()
                    if choice=="csv" and not path.endswith(".csv"):
                        path+=".csv"
                    elif choice=="excel" and not path.endswith(".xlsx"):
                        path+=".xlsx"
                    elif choice=="parquet" and not path.endswith(".parquet"):
                        path+=".parquet"
                    with open(path,"wb") as f:
                        f.write(fBytes)
                    JOptionPane.showMessageDialog(self.mainPanel,"Exported to "+path)
            else:
                eBr=BufferedReader(InputStreamReader(conn.getErrorStream(),"UTF-8"))
                eStr=""
                line=eBr.readLine()
                while line:
                    eStr+=line
                    line=eBr.readLine()
                eBr.close()
                print("[exportResults] server error =>\n",eStr)
                JOptionPane.showMessageDialog(self.mainPanel,
                                              "Error from export:\n"+eStr,
                                              "Error",
                                              JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            print("[exportResults] exception =>", e)
            JOptionPane.showMessageDialog(self.mainPanel,
                                          "Error exporting:\n"+str(e),
                                          "Error",
                                          JOptionPane.ERROR_MESSAGE)

    #
    # redactSensitive => to remove cookie, authorization
    #
    def redactSensitive(self, reqStr):
        sensitive=["cookie","authorization"]
        lines=reqStr.splitlines()
        newLines=[]
        for l in lines:
            lw=l.lower()
            if any(lw.startswith(s+":") for s in sensitive):
                parts=l.split(":",1)
                newLines.append(parts[0]+": [REDACTED]")
            else:
                newLines.append(l)
        return "\r\n".join(newLines)

    #
    # clearSelectedRows
    #
    def clearSelectedRows(self):
        rows=self.resultsTable.getSelectedRows()
        if not rows or len(rows)==0:
            JOptionPane.showMessageDialog(self.mainPanel,"No transactions selected to clear.")
            return

        rowSet=set(rows)
        oldData=[]
        for r in range(self.tableModel.getRowCount()):
            rowVals=[]
            for c in range(self.tableModel.getColumnCount()):
                val=self.tableModel.getValueAt(r,c)
                rowVals.append(val)
            oldData.append(rowVals)

        oldMsg=dict(self.messageInfos)
        newData=[]
        newMsg={}
        idx=0
        for r, rowVals in enumerate(oldData):
            if r not in rowSet:
                rowVals[0]=idx
                newData.append(rowVals)
                newMsg[idx]=oldMsg[r]
                idx+=1

        self.tableModel.setRowCount(0)
        for rowVals in newData:
            self.tableModel.addRow(rowVals)
        self.messageInfos=newMsg

    #
    # doResendRequest => re-send with updated Content-Length
    #
    def doResendRequest(self):
        edited=self.requestText.getText()
        if not edited.strip():
            print("[doResendRequest] no request text to resend.")
            return
        lines=edited.replace('\r\n','\n').split('\n')
        if not lines:
            print("[doResendRequest] empty lines => abort.")
            return
        firstL=lines[0].split()
        if len(firstL)<2:
            print("[doResendRequest] invalid request line =>", lines[0])
            return

        if firstL[-1].upper().strip()=="HTTP/2":
            firstL[-1]="HTTP/1.1"
            lines[0]=" ".join(firstL)

        hostHeader=None
        norm=[]
        for l in lines:
            s=l.rstrip('\r\n')
            if s.lower().startswith("host:"):
                hostHeader=s
            norm.append(s)

        if not hostHeader:
            print("[doResendRequest] no host header => abort.")
            return

        splitted=hostHeader.split(":",1)
        if len(splitted)<2:
            print("[doResendRequest] invalid host =>",hostHeader)
            return
        realPart=splitted[1].strip()
        if ":" in realPart:
            hp=realPart.split(":")
            host=hp[0]
            try:
                port=int(hp[1])
            except:
                port=443
        else:
            host=realPart
            port=443

        blankIdx=None
        for i,ln in enumerate(norm):
            if ln.strip()=="":
                blankIdx=i
                break
        if blankIdx is not None:
            headers=norm[:blankIdx]
            bodyLines=norm[blankIdx+1:]
        else:
            headers=norm
            bodyLines=[]

        body="\r\n".join(bodyLines)
        body_bytes=body.encode('utf-8')
        newLen=len(body_bytes)

        updated=[]
        foundLen=False
        for h in headers:
            if h.lower().startswith("content-length:"):
                updated.append("Content-Length: %d"%newLen)
                foundLen=True
            else:
                updated.append(h)
        if not foundLen and newLen>0:
            updated.append("Content-Length: %d"%newLen)

        finalHeaders="\r\n".join(updated)
        if bodyLines:
            finalReq=finalHeaders+"\r\n\r\n"+body
        else:
            finalReq=finalHeaders+"\r\n\r\n"

        class ResendThread(Runnable):
            def __init__(self, ext, finalReq, host, port):
                self.ext=ext
                self.finalReq=finalReq
                self.host=host
                self.port=port

            def run(self):
                try:
                    reqB=self.ext._helpers.stringToBytes(self.finalReq)
                    respB=self.ext._callbacks.makeHttpRequest(self.host,self.port,True,reqB)
                    if respB:
                        anResp=self.ext._helpers.analyzeResponse(respB)
                        sc=str(anResp.getStatusCode())
                        rbody=self.ext._helpers.bytesToString(respB[anResp.getBodyOffset():])[:100]
                    else:
                        sc="N/A"
                        rbody="No response"

                    anReq=self.ext._helpers.analyzeRequest(reqB)
                    heads=anReq.getHeaders()
                    if heads:
                        line0=heads[0]
                    else:
                        line0="(No line0)"
                    summary="%s (BodyLen:%d)"%(line0,len(reqB)-anReq.getBodyOffset())

                    def uiUpdate():
                        rowI=self.ext.tableModel.getRowCount()
                        self.ext.tableModel.addRow([rowI, summary, rbody, sc])
                        self.ext.messageInfos[rowI]={
                            "request": self.ext._helpers.bytesToString(reqB),
                            "response": self.ext._helpers.bytesToString(respB) if respB else ""
                        }
                    SwingUtilities.invokeLater(uiUpdate)
                except Exception as ex:
                    print("[doResendRequest] error =>",ex)

        Thread(ResendThread(self, finalReq, host, port)).start()

#
# Because we want to run Python callables in Thread(Runnable)
#
class PyRunnable(Runnable):
    def __init__(self, pyfunc):
        self.pyfunc = pyfunc
    def run(self):
        self.pyfunc()
