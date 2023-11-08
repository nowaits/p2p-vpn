import win32serviceutil
import win32service
import win32event
import os
import sys
import logging
import inspect
import time

assert sys.platform.startswith("win")


class win_p2p_vpn_serv(win32serviceutil.ServiceFramework):
    _svc_name_ = "p2p-vpn"
    _svc_display_name_ = "p2p-vpn"
    _svc_description_ = "desc"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.logger = self._getLogger()
        self.run = True

    def _getLogger(self):
        logger = logging.getLogger('p2p-vpn')

        this_file = inspect.getfile(inspect.currentframe())
        dirpath = os.path.abspath(os.path.dirname(this_file))
        handler = logging.FileHandler(os.path.join(dirpath, "p2p-vpn.log"))

        formatter = logging.Formatter(
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler.setFormatter(formatter)

        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        return logger

    def SvcDoRun(self):
        self.logger.info("service is run....")
        while self.run:
            time.sleep(1)
            pass

    def SvcStop(self):
        self.logger.info("service is stop....")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.run = False


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(win_p2p_vpn_serv)
