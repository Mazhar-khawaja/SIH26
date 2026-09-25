import unittest
from app.monitoring.logger import StructuredLogger
from pydantic import BaseModel, ValidationError

class DummyModel(BaseModel):
    user: str

class TestLogger(unittest.TestCase):
    def test_logger_serialization(self):
        logger = StructuredLogger("test_logger")

        try:
            DummyModel(user={"userName": "admin"})
        except ValidationError as e:
            # This should not raise a TypeError
            try:
                logger.warning("Test warning", error=e)
                logger.error("Test error", error=e)
            except TypeError:
                self.fail("Logger raised TypeError on serialization")

if __name__ == "__main__":
    unittest.main()
