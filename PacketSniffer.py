import logging
import subprocess
from PyQt5 import QtCore, QtGui, QtWidgets
from io import StringIO

try:
    from scapy.all import *
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    print("Get it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
Totalpkts = []


class Ui_MainWindow(object):

    def openWindow(self):
        self.window = QtWidgets.QMainWindow()
        self.ui = Ui_Otherwindow()
        self.ui.setupUi(self.window)
        self.window.show()

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1000, 1000)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        layout = QtWidgets.QVBoxLayout(self.centralwidget)

        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        layout.addWidget(self.scrollArea)
        # self.scrollArea.setGeometry(QtCore.QRect(20, 0, 781, 561))
        # self.scrollArea.setWidgetResizable(True)
        # self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 1080, 1150))
        # self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        layout = QtWidgets.QHBoxLayout(self.scrollAreaWidgetContents)
        MainWindow.setCentralWidget(self.centralwidget)

        self.horizontalLayout = QtWidgets.QHBoxLayout(self.scrollAreaWidgetContents)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout.setObjectName("verticalLayout")

        self.Interface_input = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.Interface_input.setGeometry(QtCore.QRect(420, 30, 141, 41))
        self.Interface_input.setObjectName("Interface_input")
        ####################################################
        # self.sniff.Interface = self.Interface_input.toPlainText()
        ####################################################
        self.Packets_ninput = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.Packets_ninput.setGeometry(QtCore.QRect(420, 110, 141, 41))
        self.Packets_ninput.setObjectName("Packets_ninput")
        ####################################################
        # self.sniff.NumberOfPackets=self.Packets_ninput.toPlainText()
        ####################################################
        self.filtering_input = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.filtering_input.setGeometry(QtCore.QRect(420, 200, 141, 41))
        self.filtering_input.setObjectName("filtering_input")

        self.specific_input = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.specific_input.setGeometry(QtCore.QRect(350, 710, 500, 100))
        self.specific_input.setObjectName("specific_input")

        self.specific_hexa = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.specific_hexa.setGeometry(QtCore.QRect(350, 820, 500, 100))
        self.specific_hexa.setObjectName("specific_hexa")
        #####################################################
        # self.sniff.ProtocolFilter = self.filtering_input.toPlainText()
        #####################################################
        self.Network_interface = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.Network_interface.setGeometry(QtCore.QRect(30, 40, 321, 20))
        self.Network_interface.setObjectName("Network_interface")

        self.Interface_note = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.Interface_note.setGeometry(QtCore.QRect(30, 60, 400, 20))
        self.Interface_note.setObjectName("Interface_note")

        self.Packets_no = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.Packets_no.setGeometry(QtCore.QRect(30, 120, 281, 20))
        self.Packets_no.setObjectName("Packets_no")
        self.filtering = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.filtering.setGeometry(QtCore.QRect(30, 200, 241, 20))
        self.filtering.setObjectName("filtering")

        self.filter_note = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.filter_note.setGeometry(QtCore.QRect(30, 220, 241, 20))
        self.filter_note.setObjectName("filter_note")

        self.Certain_packet = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.Certain_packet.setGeometry(QtCore.QRect(30, 620, 201, 20))
        self.Certain_packet.setObjectName("Certain_packet")

        self.hexa_packet = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.hexa_packet.setGeometry(QtCore.QRect(30, 710, 320, 20))
        self.hexa_packet.setObjectName("hexa_packet")

        self.pushButton = QtWidgets.QPushButton(self.scrollAreaWidgetContents)
        self.pushButton.setGeometry(QtCore.QRect(260, 290, 75, 50))
        self.pushButton.setObjectName("CAPTURE")

        self.pushButton2 = QtWidgets.QPushButton(self.scrollAreaWidgetContents)
        self.pushButton2.setGeometry(QtCore.QRect(500, 620, 75, 50))
        self.pushButton2.setObjectName("Select")
        self.pushButton2.setEnabled(False)
        ######################################################
        self.pushButton.clicked.connect(self.sniff)
        self.pushButton2.clicked.connect(self.showDetails)

        ######################################################

        self.Interface_output = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.Interface_output.setGeometry(QtCore.QRect(30, 400, 600, 200))
        self.Interface_output.setObjectName("sniff")

        self.select_out = QtWidgets.QTextEdit(self.scrollAreaWidgetContents)
        self.select_out.setGeometry(QtCore.QRect(420, 620, 75, 50))
        self.select_out.setObjectName("select")
        ######################################################
        # self.Interface_output.setText(self.sniff)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 767, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Packet Sniffer"))
        self.Network_interface.setText(
            _translate("MainWindow", "Please Enter the Network Interface to use in the packets capturing"))
        self.Interface_note.setText(_translate("MainWindow", "e.g:Ethernet/Wi-Fi"))
        self.Packets_no.setText(_translate("MainWindow", "Please Enter The Number of packets"))
        self.filtering.setText(_translate("MainWindow", "Please Enter a filter for the packets"))
        self.filter_note.setText(_translate("MainWindow", "e.g:Ttcp/udp/http"))
        self.Certain_packet.setText(_translate("MainWindow", "Please Enter a specific packet_no"))
        self.hexa_packet.setText(_translate("MainWindow", "Data of selected packet"))
        self.pushButton.setText(_translate("MainWindow", "CAPTURE"))
        self.pushButton2.setText(_translate("MainWindow", "SELECT"))
        # self.select_out.setText_translate("MainWindow", "SE"))
        # self.centralWidget.setText(_translate("MainWindow", "layout"))

    def ShowNetworkInterface(self):
        return conf.iface

    def showDetails(self):
        NumberOfSniffedPackets = int(self.Packets_ninput.toPlainText())
        number = self.select_out.toPlainText()
        text = str(self.select_out.toPlainText())
        selected = self.select_out.toPlainText()

        if(text.isdigit() == False or int(number) >= NumberOfSniffedPackets):
            self.specific_input.setText("Out of Range or not a number, Please Enter a valid packet")
            self.specific_hexa.setText("Out of Range or not a number, Please Enter a valid packet")
        else:
            capture = StringIO()
            save_stdout = sys.stdout
            sys.stdout = capture
            Totalpkts[int(number)].show()
            sys.stdout = save_stdout
            self.specific_input.setText(capture.getvalue())
            string3 = hexdump(Totalpkts[int(selected)], dump=True)
            self.specific_hexa.setText(string3)

    def sniff(self):
        NumberOfPackets = self.Packets_ninput.toPlainText()
        if(NumberOfPackets.isdigit() == False):
            self.Interface_output.setText("Please enter an integer in the number of packets field")
        else:

            ProtocolFilter = self.filtering_input.toPlainText()
            text = self.Interface_input.toPlainText()
            if (text == "Ethernet"):
                Interface = conf.iface
            elif (text == "Bluetooth"):
                Interface = conf.iface
            elif (text == "Wi-Fi"):
                Interface = conf.iface
            else:
                Interface = conf.iface
            Totalpkts.clear()
            pkts = sniff(count=int(NumberOfPackets), iface=Interface, filter=ProtocolFilter, timeout=50)

            total = ""
            for packet in range(int(NumberOfPackets)):
                string = "packet" + str(packet) + ":\n" + pkts[packet].sprintf(
                    "Time: %.time%   Source:  %-15s,IP.src%  Destination: %-15s,IP.dst%   Chucksum: %IP.chksum% ") + "\n"
                string2 = str(pkts[packet].summary())
                total = total + string + string2 + "\n" + "\n"
                self.Interface_output.setText(total)

            for packet in range(int(NumberOfPackets)):
                Totalpkts.append(pkts[packet])
            #enable the select push button
            self.pushButton2.setEnabled(True)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())           
