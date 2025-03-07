#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Prompt Augmenter and Payload Processor
"""

import json
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from javax.swing import (
    JPanel, JLabel, JTextField, JComboBox, JButton, 
    JTextArea, JScrollPane, JMenuItem, JOptionPane, SwingUtilities
)
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from burp import IBurpExtender, ITab, IIntruderPayloadProcessor, IContextMenuFactory, IContextMenuInvocation
from java.awt.event import ActionListener
from java.lang import String
from java.util import ArrayList

class BurpExtender(IBurpExtender, ITab, IIntruderPayloadProcessor, IContextMenuFactory):
    # Points to the local endpoint for prompt augmentation
    API_URL = "http://localhost:8000/api/v1/prompt_augmenter_payload_processor_endpoint/"
    
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Prompt Augmenter and Payload Processor")
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Create and register the custom tab
        self.panel = self.createCustomTab()
        callbacks.addSuiteTab(self)

        # Register this class as a payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # Register context menu
        callbacks.registerContextMenuFactory(self)

        print("\n==========================================")
        print("Prompt Augmentor and Payload Processor")
        print("==========================================\n")

    # -----------------------------------------------------------
    # Context Menu
    # -----------------------------------------------------------
    def createMenuItems(self, invocation):
        menu_item = JMenuItem(
            "Send to Prompt Augmenter as base prompt",
            actionPerformed=lambda event: self.handleContextMenuAction(invocation)
        )
        return [menu_item]

    def handleContextMenuAction(self, invocation):
        try:
            context = invocation.getInvocationContext()
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages or len(selected_messages) == 0:
                print("No selected messages found for context menu.")
                return

            selected_message = selected_messages[0]
            request_bytes = selected_message.getRequest()
            if request_bytes is None:
                print("No request bytes found in the selected message.")
                return

            try:
                request_str = String(request_bytes, "UTF-8")
            except Exception as e:
                print("Error decoding request bytes to UTF-8: {}".format(e))
                return

            selection_bounds = invocation.getSelectionBounds()
            if selection_bounds:
                highlighted_text = request_str.substring(selection_bounds[0], selection_bounds[1])
                print("Highlighted text: {}".format(highlighted_text))
            else:
                # Possibly Intruder fallback
                if context == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
                    highlighted_text = self.extractIntruderPayloadPositions(selected_message)
                else:
                    print("No selection bounds found. Check if text was highlighted.")
                    return

            if not highlighted_text:
                print("No highlighted text or payload positions found.")
                return

            # Update the base_prompt_field on the Swing thread
            SwingUtilities.invokeLater(lambda: self.base_prompt_field.setText(highlighted_text))
            print("Base prompt field updated in the custom tab with highlighted text.")

        except Exception as e:
            print("Error in handleContextMenuAction: {}".format(e))

    def extractIntruderPayloadPositions(self, selected_message):
        try:
            request_info = self.helpers.analyzeRequest(selected_message)
            body_offset = request_info.getBodyOffset()
            request_bytes = selected_message.getRequest()
            if not request_bytes:
                print("No request bytes found.")
                return None
            request_str = self.helpers.bytesToString(request_bytes)
            body = request_str[body_offset:]
            return body.strip() if body else None
        except Exception as e:
            print("Error extracting Intruder payload positions: {}".format(e))
            return None

    # -----------------------------------------------------------
    # ITab
    # -----------------------------------------------------------
    def getTabCaption(self):
        return "Prompt Augmentor and Payload Processor"

    def getUiComponent(self):
        return self.panel

    # -----------------------------------------------------------
    # Main Panel
    # -----------------------------------------------------------
    def createCustomTab(self):
        mainPanel = JPanel(BorderLayout())

        # We'll lay out input fields with GridBag
        input_panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.insets = Insets(5,5,5,5)

        def addField(label, comp, row):
            c.gridx = 0
            c.gridy = row
            c.weightx = 0.2
            input_panel.add(JLabel(label), c)
            c.gridx = 1
            c.weightx = 0.8
            input_panel.add(comp, c)

        # 1) Model provider combos => "Azure", "OpenAI", "Ollama", ADD "GCP"
        self.modelProviderDropdown = JComboBox(["Azure", "OpenAI", "Ollama", "GCP"])
        self.modelProviderDropdown.addActionListener(self.onModelProviderChanged)

        # 2) Model ID dropdown is dynamically populated
        self.modelIdDropdown = JComboBox()
        self.allModels = {}
        self.fetchModelsFromBackend()  
        self.populateModelIdDropdown("Azure")  # default

        addField("Model Provider:", self.modelProviderDropdown, 0)
        addField("Model ID:", self.modelIdDropdown, 1)

        # 3) Base prompt
        self.base_prompt_field = JTextField(20)
        addField("Base Prompt:", self.base_prompt_field, 2)

        # 4) Objective
        self.objective_field = JTextField(20)
        addField("Objective:", self.objective_field, 3)

        # 5) LLM Info
        self.llm_info_field = JTextField(20)
        addField("LLM Information:", self.llm_info_field, 4)

        # 6) Special notes
        self.special_notes_field = JTextField(20)
        addField("Special Notes:", self.special_notes_field, 5)

        # 7) Number of augments
        self.num_augments_field = JTextField("1", 5)
        addField("Number of Augments:", self.num_augments_field, 6)

        # 8) Augment type
        self.augment_type_dropdown = JComboBox(["Prompt Injection"])
        addField("Augment Type:", self.augment_type_dropdown, 7)

        mainPanel.add(input_panel, BorderLayout.NORTH)

        # Output area
        self.output_area = JTextArea(10,40)
        self.output_area.setEditable(False)
        scroll = JScrollPane(self.output_area)
        mainPanel.add(scroll, BorderLayout.CENTER)

        # Buttons
        btnPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        submitBtn = JButton("Submit", actionPerformed=self.handleSubmit)
        sendIntruderBtn = JButton("Send to Intruder", actionPerformed=self.sendToIntruder)
        btnPanel.add(submitBtn)
        btnPanel.add(sendIntruderBtn)
        mainPanel.add(btnPanel, BorderLayout.SOUTH)

        return mainPanel

    # -----------------------------------------------------------
    # GET /available_models => store in self.allModels
    # -----------------------------------------------------------
    def fetchModelsFromBackend(self):
        """
        Calls GET /api/v1/prompt_augmenter_payload_processor_endpoint/available_models
        expecting { "providers": { "Azure": [...], "OpenAI": [...], "Ollama": [...], "GCP":[...] } }.
        """
        fallback = {
            "Azure": ["azure-gpt-3.5","azure-gpt-4"],
            "OpenAI": ["gpt-3.5-turbo","gpt-4"],
            "Ollama": ["ollama-7b","ollama-phi4"],
            "GCP": ["gemini-2.0-flash-exp","gemini-1.5-flash-002"]
        }
        try:
            url = URL("http://localhost:8000/api/v1/prompt_augmenter_payload_processor_endpoint/available_models")
            conn = url.openConnection()
            conn.setRequestMethod("GET")
            code = conn.getResponseCode()
            if 200 <= code < 300:
                br = BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                resp = ""
                line = br.readLine()
                while line:
                    resp += line
                    line = br.readLine()
                br.close()
                data = json.loads(resp)
                providers_dict = data.get("providers", {})
                if not providers_dict:
                    providers_dict = fallback
                # ensure GCP is present
                for p in ["Azure","OpenAI","Ollama","GCP"]:
                    if p not in providers_dict:
                        providers_dict[p] = []
                self.allModels = providers_dict
            else:
                print("[fetchModelsFromBackend] Non-2xx code => fallback.")
                self.allModels = fallback
        except Exception as e:
            print("[fetchModelsFromBackend] Exception =>",str(e))
            self.allModels = fallback

    def onModelProviderChanged(self, event):
        provider = self.modelProviderDropdown.getSelectedItem()
        self.populateModelIdDropdown(provider)

    def populateModelIdDropdown(self, provider):
        self.modelIdDropdown.removeAllItems()
        if not self.allModels:
            # fallback
            self.allModels = {
                "Azure": ["azure-gpt-3.5","azure-gpt-4"],
                "OpenAI": ["gpt-3.5-turbo","gpt-4"],
                "Ollama": ["ollama-7b","ollama-phi4"],
                "GCP": ["gemini-2.0-flash-exp","gemini-1.5-flash-002"]
            }
        if provider in self.allModels:
            modelList = self.allModels[provider]
        else:
            modelList = ["NoModelsFound"]

        for m in modelList:
            self.modelIdDropdown.addItem(m)

    # -----------------------------------------------------------
    # Buttons
    # -----------------------------------------------------------
    def handleSubmit(self, event):
        """
        Builds a JSON, sends POST to self.API_URL 
        => returns {"augmented_prompt_list":[...]} => display in self.output_area.
        """
        try:
            provider_ui = self.modelProviderDropdown.getSelectedItem()
            # Expand logic to handle GCP or Azure => AzureOpenAI
            if provider_ui == "Azure":
                final_type = "AzureOpenAI"
            elif provider_ui == "GCP":
                final_type = "GCP"
            else:
                final_type = provider_ui  # "OpenAI" or "Ollama"

            model_id = self.modelIdDropdown.getSelectedItem()
            base_prompt = self.base_prompt_field.getText().strip()
            objective = self.objective_field.getText().strip()
            llm_info = self.llm_info_field.getText().strip()
            special_notes = self.special_notes_field.getText().strip()
            augment_type = self.augment_type_dropdown.getSelectedItem()

            num_aug = 1
            if self.num_augments_field.getText().isdigit():
                num_aug = int(self.num_augments_field.getText())

            payload = {
                "column_name": "prompt",
                "number_of_augments": num_aug,
                "prompt_list": [{"prompt": base_prompt}],
                "augmentor_model_type": final_type,  
                "model_type": final_type,
                "augmentor_model_id": model_id,
                "augmentor_api_key_env": "",
                "augment_types": [augment_type],
                "download_csv": False,
                "suppress_terminal_output": False,
                "objective": objective,
                "llm_information": llm_info,
                "special_notes": special_notes
            }

            resp_json = self.sendApiRequest(payload)
            augmented_list = resp_json.get("augmented_prompt_list", [])
            if augmented_list:
                display_str = "Augmented Prompt(s):\n" + "\n".join(augmented_list)
                self.output_area.setText(display_str)
            else:
                self.output_area.setText("No augmented prompts returned.")

        except Exception as e:
            self.output_area.setText("Error: " + str(e))

    def sendToIntruder(self, event):
        """
        Splits the output_area lines => registers them as an Intruder payload generator.
        """
        try:
            lines = self.output_area.getText().strip().split("\n")
            if len(lines) <= 1:
                print("No prompts to send to Intruder or insufficient lines.")
                return
            if lines[0].startswith("Augmented"):
                lines = lines[1:]  # skip label
            prompts = lines[:]

            generator_factory = AugmentedPromptGeneratorFactory(prompts)
            self.callbacks.registerIntruderPayloadGeneratorFactory(generator_factory)
            print("Prompts registered to Intruder.")
            JOptionPane.showMessageDialog(self.panel, "Prompts sent to Intruder as a custom payload set.")
        except Exception as e:
            print("Error sending prompts to Intruder: " + str(e))

    # -----------------------------------------------------------
    # Actually send the POST
    # -----------------------------------------------------------
    def sendApiRequest(self, payload):
        try:
            url = URL(self.API_URL)
            conn = url.openConnection()
            conn.setDoOutput(True)
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")

            out_stream = conn.getOutputStream()
            out_stream.write(json.dumps(payload).encode("utf-8"))
            out_stream.flush()
            out_stream.close()

            code = conn.getResponseCode()
            if code == 200:
                br = BufferedReader(InputStreamReader(conn.getInputStream(),"UTF-8"))
                resp_str = ""
                line = br.readLine()
                while line:
                    resp_str += line
                    line = br.readLine()
                br.close()
                return json.loads(resp_str)
            else:
                raise Exception("API error code: %d" % code)

        except Exception as e:
            raise Exception("Error sending API request: " + str(e))

    # -----------------------------------------------------------
    # Intruder Payload Processor
    # -----------------------------------------------------------
    def getProcessorName(self):
        return "PromptAugmentation"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        """
        For Intruder usage: 
        - Takes the current payload text
        - Submits it for exactly 1 augmentation
        - Returns the first augmented prompt if available.
        """
        try:
            curStr = self.helpers.bytesToString(currentPayload)

            provider_ui = self.modelProviderDropdown.getSelectedItem()
            if provider_ui == "Azure":
                final_type = "AzureOpenAI"
            elif provider_ui == "GCP":
                final_type = "GCP"
            else:
                final_type = provider_ui  # "OpenAI" or "Ollama"

            model_id = self.modelIdDropdown.getSelectedItem()
            objective = self.objective_field.getText().strip()
            llm_info = self.llm_info_field.getText().strip()
            special_notes = self.special_notes_field.getText().strip()
            augment_type = self.augment_type_dropdown.getSelectedItem()

            # Build payload
            api_payload = {
                "column_name": "prompt",
                "number_of_augments": 1,  
                "prompt_list": [{"prompt": curStr}],
                "augmentor_model_type": final_type,
                "model_type": final_type,
                "augmentor_model_id": model_id,
                "augmentor_api_key_env": "",
                "augment_types": [augment_type],
                "download_csv": False,
                "suppress_terminal_output": False,
                "objective": objective,
                "llm_information": llm_info,
                "special_notes": special_notes
            }

            resp_json = self.sendApiRequest(api_payload)
            augmented_list = resp_json.get("augmented_prompt_list", [])
            if augmented_list:
                return self.helpers.stringToBytes(augmented_list[0])

        except Exception as e:
            print("Error in processPayload =>", str(e))

        # fallback
        return currentPayload


# -----------------------------------------------------------
# Intruder Payload Generator
# -----------------------------------------------------------
from burp import IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator

class AugmentedPromptGeneratorFactory(IIntruderPayloadGeneratorFactory):
    def __init__(self, prompts):
        self.prompts = prompts

    def getGeneratorName(self):
        return "Augmented Prompt Generator"

    def createNewInstance(self, attack):
        return AugmentedPromptGenerator(self.prompts)

class AugmentedPromptGenerator(IIntruderPayloadGenerator):
    def __init__(self, prompts):
        self.prompts = prompts
        self.index = 0

    def hasMorePayloads(self):
        return self.index < len(self.prompts)

    def getNextPayload(self, baseValue):
        if self.index < len(self.prompts):
            payload = self.prompts[self.index]
            self.index += 1
            return payload.encode("utf-8")
        return None

    def reset(self):
        self.index = 0
