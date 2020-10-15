package org.com.util;

import java.net.URI;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.ibatis.session.SqlSession;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;

@Controller
public class CSUIInit {

	private WebSocketClient client = null;
	private Thread thread = null;
	private WSSMsg wssMsg;

	@Value("${wss.ip}")
	private String wssIp;

	@Value("${wss.onoff}")
	private String wssOnoff;

	public CSUIInit() {
	}

	public void init() {
		try {
			if (wssMsg == null) {
				wssMsg = new WSSMsg(10);
			}
			if ("true".equals(wssOnoff) == true) {
				client = new WebSocketClient(new URI(wssIp), new Draft_6455()) {

					@Override
					public void onOpen(ServerHandshake handshakedata) {
						if (client != null) {
							client.send("{\"type\":\"user_id\",\"level\":\"3\"}");
							if (thread == null) {
								thread = new Thread(new PingThread());
								thread.start();
							}
						}
					}

					@Override
					public void onMessage(String message) {
						wssMsg.pushData(message);
					}

					@Override
					public void onClose(int code, String reason, boolean remote) {
						try {
							closeSocket();
							Thread.sleep(1000);
							init();
						} catch (Exception e) {
							e.printStackTrace();
						}
					}

					@Override
					public void onError(Exception ex) {
						
					}
					
				};
				if (wssIp.startsWith("wss") == true) {
					SSLContext context = SSLContext.getInstance("TLS");
					TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
					tmf.init((KeyStore) null);
					X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
					SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
					context.init(null, new TrustManager[] {tm}, null);
					SSLSocketFactory sslSocketFactory = context.getSocketFactory();
					client.setSocketFactory(sslSocketFactory);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void closeSocket() {
		try {
			if (client != null) {
				client.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			client = null;
		}
	}

	private class WSSMsg {

		private WSSMsgThread arr[] = null;
		private int nMaxThread = 0;
		private int nCount = 0;

		public WSSMsg(int nMaxThread) {
			this.nMaxThread = nMaxThread;
			this.arr = new WSSMsgThread[this.nMaxThread];

			for (int i = 0; i < this.nMaxThread; ++i) {
				this.arr[i] = new WSSMsgThread(i);
				this.arr[i].runThread();
			}
		}

		public void pushData(String value) {
			synchronized (this) {
				this.arr[this.nCount].pushData(value);
				this.nCount = (this.nCount + 1) % this.nMaxThread;

			}
		}
	}

	private class WSSMsgThread implements Runnable {

		private int index = 0;
		private Thread thread = null;
		private ArrayList<String> msg = new ArrayList<String>();

		public WSSMsgThread(int index) {
			this.index = index;
		}

		public void runThread() {
			if (this.thread == null) {
				this.thread = new Thread(this);
				this.thread.start();
			}

		}

		public void pushData(String value) {
			synchronized (this) {
				this.msg.add(value);
			}
		}

		public synchronized String popData() {

			String result = null;

			synchronized (this) {
				if (this.msg.size() > 0) {
					result = this.msg.get(0);
					this.msg.remove(0);
				}
			}

			return result;
		}

		@Override
		public void run() {
			String value = null;
			while (!Thread.interrupted()) {
				try {
					value = popData();
					if (value != null) {

					}
					Thread.sleep(100);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			thread = null;
			closeSocket();
		}

	}
	
	
	private class PingThread implements Runnable{
		
		public PingThread() {
			
		}

		@Override
		public void run() {
			while(!Thread.interrupted()) {
				try {
					if (client != null) {
						client.send("{\"type\":\"ping\"}");
					}else {
						try {
							closeSocket();
							Thread.sleep(1000);
							init();
						} catch (Exception ex) {
							ex.printStackTrace();
						}
					}
					Thread.sleep(20000);
				} catch (Exception e) {
					e.printStackTrace();
				}
				
			}
			
			thread = null;
			closeSocket();
		}
		
	}
	
	private static class SavingTrustManager implements X509TrustManager {

		private final X509TrustManager tm;
		private X509Certificate[] chain;

		public SavingTrustManager(X509TrustManager tm) {
			this.tm = tm;
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}

	}
}
