"""One error type for anything we want to show the user nicely."""


class AppError(Exception):
    def __init__(self, status, code, message, hint=None):
        super().__init__(message)
        self.status, self.code, self.message, self.hint = status, code, message, hint

    def to_dict(self):
        return {"error": {"code": self.code, "message": self.message, "hint": self.hint}}
