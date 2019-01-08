Hadoop PCAP library
===================

#exapmle

	ADD JAR hadoop-pcap-serde-1.2-SNAPSHOT-jar-with-dependencies.jar;
	SET hive.input.format=org.apache.hadoop.hive.ql.io.CombineHiveInputFormat;
	SET mapred.max.split.size=104857600;
	SET net.ripe.hadoop.pcap.io.reader.class=net.ripe.hadoop.pcap.XiaofeiPacketReader;

	CREATE EXTERNAL TABLE a54(ts_usec double,
								 protocol string,
								 src string,
								 src_port int,
								 dst string,
								 dst_port int,
								 src_mac string,
								 dst_mac string,
								 host string,
								 ori_len bigint,
								 user_ip string,
								 from_to string,
								 user_mac string)

	ROW FORMAT SERDE 'net.ripe.hadoop.pcap.serde.PcapDeserializer'
	STORED AS INPUTFORMAT 'net.ripe.hadoop.pcap.mr1.io.PcapInputFormat'
			  OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
	LOCATION 'hdfs://192.168.1.117:9000/zhangheng/caps';
	
#Dump code
	ADD JAR hadoop-pcap-serde-1.2-SNAPSHOT-jar-with-dependencies.jar;SET hive.input.format=org.apache.hadoop.hive.ql.io.CombineHiveInputFormat;SET mapred.max.split.size=104857600;SET net.ripe.hadoop.pcap.io.reader.class=net.ripe.hadoop.pcap.XiaofeiPacketReader;CREATE EXTERNAL TABLE a100(ts_usec double,protocol string,src string,src_port int,dst string,dst_port int,src_mac string,dst_mac string,host string,ori_len bigint,user_ip string,from_to string,user_mac string) ROW FORMAT SERDE 'net.ripe.hadoop.pcap.serde.PcapDeserializer' STORED AS INPUTFORMAT 'net.ripe.hadoop.pcap.mr1.io.PcapInputFormat' OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat' LOCATION 'hdfs://192.168.1.117:9000/zhangheng/caps';SELECT * FROM a100;