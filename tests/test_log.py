import unittest
from unittest.mock import patch
from tbcml import core


class TestLogger(unittest.TestCase):
    def setUp(self):
        self.logger = core.Logger()

    def test_log_debug(self):
        with patch.object(self.logger.log_file, "write") as mock_write:
            self.logger.log_debug("Debug message")
            mock_write.assert_called_once_with(
                core.Data(
                    "\n[DEBUG]::{} - Debug message".format(self.logger.get_time())
                )
            )

    def test_log_info(self):
        with patch.object(self.logger.log_file, "write") as mock_write:
            self.logger.log_info("Info message")
            mock_write.assert_called_once_with(
                core.Data("\n[INFO]::{} - Info message".format(self.logger.get_time()))
            )

    def test_log_warning(self):
        with patch.object(self.logger.log_file, "write") as mock_write:
            self.logger.log_warning("Warning message")
            mock_write.assert_called_once_with(
                core.Data(
                    "\n[WARNING]::{} - Warning message".format(self.logger.get_time())
                )
            )

    def test_log_error(self):
        with patch.object(self.logger.log_file, "write") as mock_write:
            self.logger.log_error("Error message")
            mock_write.assert_called_once_with(
                core.Data(
                    "\n[ERROR]::{} - Error message".format(self.logger.get_time())
                )
            )

    def test_log_no_file_found(self):
        with patch.object(self.logger.log_file, "write") as mock_write:
            self.logger.log_no_file_found("file.txt")
            mock_write.assert_called_once_with(
                core.Data(
                    "\n[WARNING]::{} - Could not find file.txt".format(
                        self.logger.get_time()
                    )
                )
            )
