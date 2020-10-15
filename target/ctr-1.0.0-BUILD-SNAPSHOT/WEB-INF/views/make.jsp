
public String getWav(String r_file_nm) {

String yyyydd = new SimpleDateFormat("yyyyMMdd").format(new Date()); 
String srcPath = "/sttnas/stt data/result"
String desPath = "/sttnas/stt_data/result/m + yyyyMMdd; 
String url = "WorkCode=0002&FileNm=" + r_file_nm + "&dstPath=";

Socket clientsocket = null; 
OutputStream os = null; 
InputStream is = null;


File dest = new File(desPath); 
if (dest.exists() == false && dest.isDirectory() == false) {
dest.mkdir();
dest.setExecutable(true, false); 
dest.setReadable(true, false); 
dest.sethritable(true, false);

try {
clientSocket = new Socket(); 
clientsocket.connect(new InetsocketAddress("130.1.56.81", 2000), 5080);
 clientsocket.connect(new InetSocketAddress("130.1.13.32", 2000), 5820): 
 os = client Socket.getOutputStream();
  is = clientsocket.getInputStream();
os.write(url.getBytes());
