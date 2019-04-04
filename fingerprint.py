#!usr/bin/python3

from struct import pack, unpack
import serial
import binascii
import time


class R30X:
    header_pckt = 0xef01
    addr_pckt = 0xffffffff
    identifier_pckt = 0x1
    instruction_code = {
        'VfyPwd' : 0x13, 
        'SetPwd' : 0x12,
        'SetSysParam' : 0x0e,
        'genImg' : 0x1,
        'Img2Tz' : 0x2,
        'RegModel' : 0x5,
        'Store' : 0x6,
        'LoadChar' : 0x7,
        'DeleteChar' : 0x0c,
        'EmptyChar' : 0x0d,
        'Match' : 0x3,
    }
    def __init__(self, ser, response_type="text"): 
        self.ser = ser
        if response_type not in ['text', 'hex', 'both']:
            raise Exception("Invalid value for response_type set (response type is either >>\"text\"<< or >>\"hex\"<< or >>\"both\"<<")
        self.response_type = response_type #setting to text returns the text response and 
                                           #setting to hex returns the hex response
        self.hdr_addr_iden = [R30X.header_pckt, R30X.addr_pckt, R30X.identifier_pckt]
    
    def send_command(self, instruction, data, reason=""):
        time.sleep(0.3)
        checksum_size = 2 # in bytes
        code = R30X.instruction_code[instruction] # get the instruction code from instruction(e.g 'VfyPwd' gives 0x13)
        data.insert(0, code) # put the instruction code before the data according to datasheet
        len_pckt = self.data_len + checksum_size + 1  # calculate the packet length
        checksum_pckt = sum(self.hdr_addr_iden[-1:] + [len_pckt] + data) # calculate the checksum
        packet = self.hdr_addr_iden + [len_pckt] + data + [checksum_pckt]
        if reason=="extra2bytes":
            binary_packet = pack('!HIBH' + 'B'*2 + 'H' + 'H', *packet)
        else:
            binary_packet = pack('!HIBH'+'B'*(self.data_len+1) + 'H', *packet)
        return binary_packet

    def recieve_ack_only(self, reason=""):
        time.sleep(0.7)
        in_buffer = self.ser.inWaiting()
        ack = []
        if in_buffer > 9:
            binary_packet = self.ser.read(9)
            packet = unpack('!HIBH', binary_packet)
            ack.extend(packet)
            package_len = packet[-1]
            in_buffer = self.ser.inWaiting()
            
            if in_buffer > 1:
                binary_packet = self.ser.read(package_len)
                if reason == "fingermatch":
                    packet = unpack('!B'*(package_len-4)+'HH', binary_packet)
                else:
                    packet = unpack('!B'*(package_len-2)+'H', binary_packet)
                ack.extend(packet)
        return ack
    
    def recieve_ack_data(self):
        pass
        
    def verifyPassword(self, password=[0x0, 0x0, 0x0, 0x0]):
        VfyPwdResp = {
            0x0  :  "Correct Password",
            0x1  :  "Error When Receiving Package",
            0x13 :  "Wrong Password"
        }
        self.data_len = len(password)
        if self.data_len != 4:  #password must be 4 bytes
            raise Exception("Password must be 4 bytes")
        binary_pckt = self.send_command('VfyPwd', password)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[3]
        elif self.response_type == "both":
            return (ack[4], VfyPwdResp[ack[4]])
        else:
            return VfyPwdResp[ack[4]]

    def setPassword(self, password):
        SetPwdResp = {
            0x0  :  "Password Setting Complete",
            0x1  :  "Error When Receiving Package"
        }
        self.data_len = len(password)
        if self.data_len != 4:
            raise Exception("Password must be 4 bytes")
        binary_pckt = self.send_command('SetPwd', password)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], SetPwdResp[ack[4]])
        else:
            return SetPwdResp[ack[4]]

    def setSysParameters(self, param_num, contents):
        if param_num == 4:    #Baud Rate Control (contents or N = 1,2,3....12  * 9600)
            if contents not in range(1,13):
                raise Exception('Content out of range')
        elif param_num == 5:  #Security Level( contents of N = 1,2....5)
            if contents not in range(1,6):
                raise Exception('Content out of range')
        elif param_num == 6:  #Maximum Data Package length (contents or N = 0, 1, 2, 3 corresponding to 32, 64, 128, 256)
            if contents not in range(4):
                raise Exception('Content out of range')
        else:
            raise Exception('Wrong Parameter Number')
        
        SetSysParamResp = {
            0x0  :  "Parameter Setting Complete",
            0x1  :  "Error When Receiving Package"
        }
        data = [param_num, contents]
        self.data_len = 2
        binary_pckt = self.send_command('SetSysParam', data)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], SetSysParamResp[ack[4]])
        else:
            return SetSysParamResp[ack[4]]

    def getSysParameters(self, para):
        pass

    def generateImage(self):
        GenImgResp = {
            0x0  :  "Finger Collection Success",
            0x1  :  "Error When Receiving Package",
            0x2  :  "Can't Detect Finger",
            0x3  :  "Failed To Collect Finger"
        }
        data = []
        self.data_len = 0
        binary_pckt = self.send_command('genImg', data)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], GenImgResp[ack[4]])
        else:
            return GenImgResp[ack[4]]
        
    def imageToCharacter(self, buffer_id):
        if buffer_id not in (1,2):
            raise Exception('Just two buffer ids exist ... 1 and 2')
        Img2TzResp = {
            0x0  :  "Generate Character Complete",
            0x1  :  "Error When Receiving Package",
            0x6  :  "Fail To Generate Character File Due To Over-Disorderly Fingerprint Image",
            0x7  :  "Fail To Generate Character File Due To Lackness Of Character Point Or Over-Smallness Of Fingerprint Image",
            0x15 :  "Fail To Generate The Image For The Lackness of Valid Primary Image"
        }
        data = [buffer_id]
        self.data_len = 1
        binary_pckt = self.send_command('Img2Tz', data)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], Img2TzResp[ack[4]])
        else:
            return Img2TzResp(ack[4])

    def generateTemplate(self):
        RegModelResp = {
            0x0  :  "Operation Success",
            0x1  :  "Error When Receiving Package",
            0xa  :  "Fail To Combine The Character Files",
        }
        data = []
        self.data_len = 0
        binary_pckt = self.send_command('RegModel', data)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], RegModelResp[ack[4]])
        else:
            return RegModelResp(ack[4])

    def storeTemplate(self, buffer_id, page_id):
        if buffer_id not in (1,2):
            raise Exception('Just two buffer ids exist ... 1 and 2')
        StoreResp = {
            0x0  :  "Storage Success",
            0x1  :  "Error When Receiving Package",
            0x0b  :  "Addressing Page ID Is Beyond The Finger Library",
            0x18  :  "Error When Writing To Flash"
        }
        data = [buffer_id, page_id]
        self.data_len = 3
        binary_pckt = self.send_command('Store', data, 'extra2bytes')
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], StoreResp[ack[4]])
        else:
            return StoreResp(ack[4])

    def loadTemplate(self, buffer_id, page_id):
        if buffer_id not in (1,2):
            raise Exception('Just two buffer ids exist ... 1 and 2')
        LoadCharResp = {
            0x0  :  "Load Success",
            0x1  :  "Error When Receiving Package",
            0x0c  :  "Error When Reading Template From Library Or The Readout Template Is Invalid",
            0x0b  :  "Addressing Page Id Is Beyond The FingerPrint Library"
        }
        data = [buffer_id, page_id]
        self.data_len = 3
        binary_pckt = self.send_command('LoadChar', data, 'extra2bytes')
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], LoadCharResp[ack[4]])
        else:
            return LoadCharResp[ack[4]]

    def deleteTemplate(self, page_id, num_of_templates):
        DeleteCharResp = {
            0x0  :  "Delete Success",
            0x1  :  "Error When Receiving Package",
            0x10  :  "Failed To Delete Template",
        }
        data = [page_id, num_of_templates]
        self.data_len = 4
        binary_pckt = self.send_command("DeleteChar", data, 'extra2bytes')
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], DeleteCharResp[ack[4]])
        else:
            return DeleteCharResp[ack[4]]

    def emptyTemplate(self):
        EmptyCharResp = {
            0x0  :  "Empty Success",
            0x1  :  "Error When Receiving Package",
            0x11  :  "Failed To Clear Fingerprint Library"
        }
        data = []
        self.data_len = 0
        binary_pckt = self.send_command("EmptyChar", data)
        self.ser_write(binary_pckt)
        ack = self.recieve_ack_only()
        if self.response_type == "hex":
            return ack[4]
        elif self.response_type == "both":
            return (ack[4], DeleteCharResp[ack[4]])
        else: 
            return DeleteCharResp[ack[4]]

    def preciseFingerMatch(self):
        MatchResp = {
            0x0  :  "Templates Of The Two Buffers Are Matching",
            0x1  :  "Error When Receiving Package",
            0x8  :  "Templates Of The Two Buffers Are Not Matching"
        }
        data = []
        self.data_len = 0
        binary_pckt = self.send_command("Match", data)
        self.ser.write(binary_pckt)
        ack = self.recieve_ack_only("fingermatch")
        if self.response_type == "hex":
            return (ack[5], ack[4])
        elif self.response_type == "both":
            return (ack[5], ack[4], MatchResp[ack[4]])
        else: 
            return (ack[5], MatchResp[ack[4]])




