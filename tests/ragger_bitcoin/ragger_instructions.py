from ragger.navigator import NavInsID


class Instructions:
    def __init__(self, model):
        self.data = {
            'text': [],
            'instruction_until_text': [],
            'instruction_on_text': [],
            'save_screenshot': []
        }

        if not model:
            raise Exception("Model must be specified")

        self.model = model

    def __str__(self):
        return "Data: {0}\n\t".format(self.data)

    def no_snapshots(self):
        """Navigates on the expected text alone, for tests that check status words."""
        self.data['save_screenshot'] = [[False] * len(request)
                                        for request in self.data['save_screenshot']]
        return self

    def same_request(self, text, instruction_until_text=NavInsID.RIGHT_CLICK,
                     instruction_on_text=NavInsID.BOTH_CLICK, save_screenshot=True):

        self.data['text'][-1].append(text)
        self.data['instruction_until_text'][-1].append(instruction_until_text)
        self.data['instruction_on_text'][-1].append(instruction_on_text)
        self.data['save_screenshot'][-1].append(save_screenshot)

    def new_request(self, text, instruction_until_text=NavInsID.RIGHT_CLICK,
                    instruction_on_text=NavInsID.BOTH_CLICK, save_screenshot=True):

        self.data['text'].append([text])
        self.data['instruction_until_text'].append([instruction_until_text])
        self.data['instruction_on_text'].append([instruction_on_text])
        self.data['save_screenshot'].append([save_screenshot])

    def nano_skip_screen(self, text, save_screenshot=True):
        self.new_request(text, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK,
                         save_screenshot=save_screenshot)

    def navigate_end_of_flow(self, save_screenshot=True):
        self.new_request("Processing", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                         save_screenshot=save_screenshot)

    def review_start(self, output_count: int = 1, save_screenshot=True):
        self.new_request("Review", NavInsID.SWIPE_CENTER_TO_LEFT, NavInsID.SWIPE_CENTER_TO_LEFT,
                         save_screenshot=save_screenshot)
        for _ in range(0, output_count):
            self.same_request("Amount", NavInsID.SWIPE_CENTER_TO_LEFT, NavInsID.SWIPE_CENTER_TO_LEFT,
                         save_screenshot=save_screenshot)
    def review_fees(self, fees_on_same_request: bool = True, save_screenshot=True):
        if fees_on_same_request:
            self.same_request("Fees", NavInsID.SWIPE_CENTER_TO_LEFT, NavInsID.SWIPE_CENTER_TO_LEFT,
                         save_screenshot=save_screenshot)
        else:
            self.new_request("Fees", NavInsID.SWIPE_CENTER_TO_LEFT, NavInsID.SWIPE_CENTER_TO_LEFT,
                         save_screenshot=save_screenshot)

    def confirm_transaction(self, save_screenshot=True):
        self.same_request("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM,
                          save_screenshot=save_screenshot)
        self.new_request("Transaction", NavInsID.USE_CASE_REVIEW_TAP,
                         NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def confirm_message(self, save_screenshot=True):
        self.new_request("Sign", NavInsID.SWIPE_CENTER_TO_LEFT,
                         NavInsID.USE_CASE_REVIEW_CONFIRM, save_screenshot=save_screenshot)
        self.new_request("Message", NavInsID.SWIPE_CENTER_TO_LEFT,
                         NavInsID.USE_CASE_STATUS_DISMISS, save_screenshot=save_screenshot)

    def confirm_wallet(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_CONFIRM,
                         save_screenshot=save_screenshot)
        self.same_request("Wallet", NavInsID.USE_CASE_REVIEW_TAP,
                          NavInsID.USE_CASE_STATUS_DISMISS, save_screenshot=save_screenshot)

    def reject_message(self, save_screenshot=True):
        self.new_request("Sign", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_REJECT,
                         save_screenshot=save_screenshot)
        self.same_request("Reject", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                          save_screenshot=save_screenshot)
        self.new_request("MESSAGE", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_STATUS_DISMISS,
                         save_screenshot=save_screenshot)

    def warning_accept(self, save_screenshot=True):
        self.new_request("Warning", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)

    def address_confirm(self, save_screenshot=True):
        self.new_request("Confirm", NavInsID.SWIPE_CENTER_TO_LEFT,
                         NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                         save_screenshot=save_screenshot)

    def choice_confirm(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_CONFIRM,
                         save_screenshot=save_screenshot)

    def choice_reject(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_CHOICE_REJECT,
                         save_screenshot=save_screenshot)

    def footer_cancel(self, save_screenshot=True):
        self.new_request("Approve", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.CANCEL_FOOTER_TAP,
                         save_screenshot=save_screenshot)
