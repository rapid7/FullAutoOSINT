from core.actionModule import actionModule

class osintModule(actionModule):
    def __init__(self, config, display, lock):
        super(osintModule, self).__init__(config, display, lock)
        self.safeLevel = 5
