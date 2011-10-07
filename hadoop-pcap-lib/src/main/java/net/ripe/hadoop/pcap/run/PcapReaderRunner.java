package net.ripe.hadoop.pcap.run;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.zip.GZIPInputStream;

import net.ripe.hadoop.pcap.PcapReader;
import net.ripe.hadoop.pcap.packet.Packet;

public class PcapReaderRunner {
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if(args.length != 2){
            System.err.println("Usage: net.ripe.hadoop.pcap.run.PcapReaderRunner net.ripe.hadoop.pcap.PcapReader|net.ripe.hadoop.pcap.DnsPcapReader /path/to/pcap_file");
            return;
        }

		try {
			new PcapReaderRunner().run(args[0], args[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void run(String pcapReaderClass, String path) throws IOException {
		InputStream is = null;
		try {
			System.out.println("=== START ===");

			is = new FileInputStream(path);
			if (path.endsWith(".gz") || path.endsWith(".gzip"))
				is = new GZIPInputStream(is);
			is = new BufferedInputStream(is);

			PcapReader reader = initPcapReader(pcapReaderClass, is);
	
			for (Packet packet : reader) {
				System.out.println("--- packet ---");
				System.out.println(packet.toString());
			}
			System.out.println("=== STOP ===");
		} finally {
			if (is != null)
				is.close();
		}
	}

	private PcapReader initPcapReader(String className, InputStream is) {
		try {
			@SuppressWarnings("unchecked")
			Class<PcapReader> pcapReaderClass = (Class<PcapReader>)Class.forName(className);
			Constructor<PcapReader> pcapReaderConstructor = pcapReaderClass.getConstructor(InputStream.class);
			return pcapReaderConstructor.newInstance(is);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}