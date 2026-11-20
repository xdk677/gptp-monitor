"""Desktop entry point for the Windows gPTP monitor."""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Windows gPTP GUI")
    parser.add_argument("--offscreen", action="store_true")
    parser.add_argument("--smoke-ui", action="store_true")
    args = parser.parse_args(argv)
    if args.offscreen:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    application = QtWidgets.QApplication.instance()
    owns_application = application is None
    if application is None:
        application = QtWidgets.QApplication([sys.argv[0]])
    window = MainWindow()
    window.show()
    if args.smoke_ui:
        application.processEvents()
        window.close()
        window.deleteLater()
        application.processEvents()
        return 0
    return application.exec_() if owns_application else 0


if __name__ == "__main__":
    raise SystemExit(main())
