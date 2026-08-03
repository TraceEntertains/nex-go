package nex

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type RawRMCWriter struct {
	Connection *PRUDPConnection
	TitleID    uint64
	fileHandle *os.File
	fileWriter *bufio.Writer
	startTime  time.Time
}

const MAX_PACKET_LENGTH = 65535
const RAW_RMC_HEADER_LENGTH = 10 // revision + titleID + flags

func NewRawRMCWriter(connection *PRUDPConnection, titleID uint64) *RawRMCWriter {
	return &RawRMCWriter{
		Connection: connection,
		TitleID:    titleID,
	}
}

func (rrmcw *RawRMCWriter) PrepareWriting() {
	startTime := time.Now().UTC()

	if _, err := os.Stat("pcaps"); os.IsNotExist(err) {
		os.Mkdir("pcaps", os.ModeDir|0755)
	}

	fileHandle, err := os.Create(fmt.Sprintf("./pcaps/rawrmc_pid%d_sid%d_%s.pcap", rrmcw.Connection.PID(), rrmcw.Connection.StreamID, startTime.Format("2006-01-02_15-04-05")))
	if err != nil {
		logger.Errorf("Failed to create capture for PID %d! Error: %s", rrmcw.Connection.PID(), err.Error())
	}

	rrmcw.fileHandle = fileHandle

	pcapHeader := binary.LittleEndian.AppendUint32([]byte{}, 0xA1B23C4D)         // Magic number (nanosecond res)
	pcapHeader = binary.LittleEndian.AppendUint16(pcapHeader, 2)                 // Major version
	pcapHeader = binary.LittleEndian.AppendUint16(pcapHeader, 4)                 // Minor version
	pcapHeader = binary.LittleEndian.AppendUint32(pcapHeader, 0)                 // Reserved
	pcapHeader = binary.LittleEndian.AppendUint32(pcapHeader, 0)                 // Reserved 2
	pcapHeader = binary.LittleEndian.AppendUint32(pcapHeader, MAX_PACKET_LENGTH) // Max len
	pcapHeader = binary.LittleEndian.AppendUint32(pcapHeader, 0x93)              // Link type (hokakuctr)

	writer := bufio.NewWriter(fileHandle)
	writer.Write(pcapHeader)
	writer.Flush()

	rrmcw.fileWriter = writer
	rrmcw.startTime = startTime
}

func (rrmcw *RawRMCWriter) CaptureRMCData(packet PRUDPPacketInterface, isFromServer bool) {
	messageData := []byte{}
	// This is because we deserialize to RMCMessage on inbound packets and only use packet.SetPayload() for outgoing ones.
	// Probably could use packet.Payload() on both but oh well...
	if isFromServer && packet.RMCMessage() == nil && packet.Payload() != nil {
		messageData = packet.Payload()
	} else if !isFromServer && packet.RMCMessage() != nil {
		messageData = packet.RMCMessage().Bytes()
	}

	messageDataLen := uint32(len(messageData))
	if messageDataLen < 4 {
		return
	}

	if messageDataLen > MAX_PACKET_LENGTH-RAW_RMC_HEADER_LENGTH {
		logger.Warningf("Could not log packet for PID %d, too large! Limit is %d, size was %d", rrmcw.Connection.PID(), MAX_PACKET_LENGTH-RAW_RMC_HEADER_LENGTH, messageDataLen)
		return
	}

	packetTime := time.Now().UTC()

	elapsed := packetTime.Sub(rrmcw.startTime)
	sec := uint32(elapsed / time.Second)
	nsec := uint32(elapsed % time.Second)

	packetHeader := binary.LittleEndian.AppendUint32([]byte{}, sec)
	packetHeader = binary.LittleEndian.AppendUint32(packetHeader, nsec)
	packetHeader = binary.LittleEndian.AppendUint32(packetHeader, messageDataLen+RAW_RMC_HEADER_LENGTH)
	packetHeader = binary.LittleEndian.AppendUint32(packetHeader, messageDataLen+RAW_RMC_HEADER_LENGTH)

	flags := byte(0)
	if isFromServer {
		flags |= 0x1
	}

	packetMeta := []byte{1}                                                  // Revision
	packetMeta = binary.LittleEndian.AppendUint64(packetMeta, rrmcw.TitleID) // Title ID
	packetMeta = append(packetMeta, byte(flags)&0x1)                         // Flags

	rrmcw.fileWriter.Write(packetHeader)
	rrmcw.fileWriter.Write(packetMeta)
	rrmcw.fileWriter.Write(messageData)
	rrmcw.fileWriter.Flush()
}

func (rrmcw *RawRMCWriter) CloseWriting() {
	if rrmcw.fileHandle != nil {
		rrmcw.fileHandle.Close()
	}
}
