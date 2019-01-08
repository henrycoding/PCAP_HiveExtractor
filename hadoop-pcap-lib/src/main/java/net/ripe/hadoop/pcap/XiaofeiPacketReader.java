package net.ripe.hadoop.pcap;

import com.google.common.base.Joiner;
import net.ripe.hadoop.pcap.packet.DnsPacket;
import net.ripe.hadoop.pcap.packet.HttpPacket;
import net.ripe.hadoop.pcap.packet.Packet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.*;
import org.apache.http.Header;
import org.apache.http.impl.DefaultHttpRequestFactory;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.conn.DefaultClientConnection;
import org.apache.http.impl.io.AbstractSessionInputBuffer;
import org.apache.http.impl.io.AbstractSessionOutputBuffer;
import org.apache.http.impl.io.DefaultHttpRequestParser;
import org.apache.http.impl.io.DefaultHttpResponseParser;
import org.apache.http.io.HttpMessageParser;
import org.apache.http.io.SessionInputBuffer;
import org.apache.http.io.SessionOutputBuffer;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.xbill.DNS.*;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class XiaofeiPacketReader extends PcapReader {
    public static final Log LOG = LogFactory.getLog(XiaofeiPacketReader.class);
    public static final int HTTP_PORT = 80;
    public static final String HEADER_PREFIX = "header_";
    public static final int DNS_PORT = 53;

    private HttpParams params = new BasicHttpParams();
    private HttpRequestFactory reqFactory = new DefaultHttpRequestFactory();
    private HttpResponseFactory respFactory = new DefaultHttpResponseFactory();

    public XiaofeiPacketReader(DataInputStream is) throws IOException {
        super(is);
    }

    @Override
    protected Packet createPacket() {
        return new Packet();
    }

    @Override
    protected boolean isReassembleDatagram() {
        return true;
    }

    @Override
    protected boolean isReassembleTcp() {
        return true;
    }

    @Override
    protected boolean isPush() {
        return false;
    }


    @Override
    protected void processPacketPayload(Packet packet, final byte[] payload) {
        try {

            String dst = (String) packet.get(Packet.DST);
            String src = (String) packet.get(Packet.SRC);
            if(src.startsWith("10.") && !src.equals("10.101.2.114")){
                packet.put("user_ip", src);
                packet.put("user_mac", packet.get(Packet.SRC_MAC));
                packet.put("from_to", "from");
            } else {
                packet.put("user_ip", dst);
                packet.put("user_mac", packet.get(Packet.DST_MAC));
                packet.put("from_to", "to");
            }

            String protocol = (String) packet.get(Packet.PROTOCOL);

            if (PcapReader.PROTOCOL_TCP.equals(protocol)) {
                Packet httpPacket = packet;
                Integer srcPort = (Integer) packet.get(Packet.SRC_PORT);
                Integer dstPort = (Integer) packet.get(Packet.DST_PORT);
                if ((HTTP_PORT == srcPort || HTTP_PORT == dstPort)) {
                    try {
                        String s = new String(payload, "UTF-8");
                        int pos = s.indexOf("Host") + 4;
                        s = s.substring(pos);
                        s = s.substring(0, s.indexOf("\n"));
                        packet.put("h", s);
                    } catch (Exception e) {

                    }
                }
            }

            if (DNS_PORT == (Integer) packet.get(Packet.SRC_PORT) || DNS_PORT == (Integer) packet.get(Packet.DST_PORT)) {
                byte[] payload_new = payload;
                if (PROTOCOL_TCP.equals(protocol) &&
                        payload.length > 2) // TODO Support DNS responses with multiple messages (as used for XFRs)
                    payload_new = Arrays.copyOfRange(payload, 2, payload.length); // First two bytes denote the size of the DNS message, ignore them

                try {
                    Message msg = new Message(payload_new);
                    org.xbill.DNS.Header header = msg.getHeader();
                    packet.put(DnsPacket.QUERYID, header.getID());
                    packet.put(DnsPacket.FLAGS, header.printFlags());
                    packet.put(DnsPacket.QR, header.getFlag(Flags.QR));
                    packet.put(DnsPacket.OPCODE, Opcode.string(header.getOpcode()));
                    packet.put(DnsPacket.RCODE, Rcode.string(header.getRcode()));
                    packet.put(DnsPacket.QUESTION, convertRecordToString(msg.getQuestion()));
                    packet.put(DnsPacket.QNAME, convertRecordOwnerToString(msg.getQuestion()));
                    packet.put(DnsPacket.QTYPE, convertRecordTypeToInt(msg.getQuestion()));
                    packet.put(DnsPacket.ANSWER, convertRecordsToStrings(msg.getSectionArray(Section.ANSWER)));
                    packet.put("h", msg.getSectionArray(Section.ANSWER)[0]);
                    packet.put(DnsPacket.AUTHORITY, convertRecordsToStrings(msg.getSectionArray(Section.AUTHORITY)));
                    packet.put(DnsPacket.ADDITIONAL, convertRecordsToStrings(msg.getSectionArray(Section.ADDITIONAL)));
                } catch (Exception e) {
                    // If we cannot decode a DNS packet we ignore it
                }
            }
        }catch (Exception e){

        }
    }

    private String convertRecordToString(Record record) {
        if (record == null)
            return null;

        String recordString = record.toString();
        recordString = normalizeRecordString(recordString);
        return recordString;
    }

    private String convertRecordOwnerToString(Record record) {
        if (record == null)
            return null;
        String ownerString = record.getName().toString();
        ownerString = ownerString.toLowerCase();
        return ownerString;
    }

    private int convertRecordTypeToInt(Record record) {
        if (record == null)
            return -1;
        return record.getType();
    }

    private List<String> convertRecordsToStrings(Record[] records) {
        if (records == null)
            return null;

        ArrayList<String> retVal = new ArrayList<String>(records.length);
        for (Record record : records)
            retVal.add(convertRecordToString(record));
        return retVal;
    }

    protected String normalizeRecordString(String recordString) {
        if (recordString == null)
            return null;

        // Reduce everything that is more than one whitespace to a single whitespace
        recordString = recordString.replaceAll("\\s{2,}", " ");
        // Replace tabs with a single whitespace
        recordString = recordString.replaceAll("\\t{1,}", " ");
        return recordString;
    }


    private void propagateHeaders(Packet packet, Header[] headers) {
        LinkedList<String> headerKeys = new LinkedList<String>();
        for (Header header : headers) {
            String headerKey = HEADER_PREFIX + header.getName().toLowerCase();
            headerKeys.add(headerKey);
            packet.put(headerKey, header.getValue());
        }
        packet.put(HttpPacket.HTTP_HEADERS, Joiner.on(',').join(headerKeys));
    }
}
