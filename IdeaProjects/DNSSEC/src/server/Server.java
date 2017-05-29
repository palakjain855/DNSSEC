package server;

import algorithms.Encrypt;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

public class Server {
    private ServerSocket socket;

    public Server() {
        // TODO Auto-generated constructor stub
        try {
            JsonReader reader = Json.createReader(new FileInputStream("data" + File.separator + "server.json"));
            assert reader != null;

            try {
                socket = new ServerSocket(reader.readObject().getInt("port"));

                Logger.getGlobal().info(getClass().getName() + ": Socket listening to port: " + socket.getLocalPort() + "");

                Executor executor = Executors.newFixedThreadPool(10);
                while (true) {
                    Socket s = socket.accept();
                    executor.execute(new ServerTask(s));
                }

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Server();
    }

    private class ServerTask implements Runnable {
        private Socket s;

        public ServerTask(Socket s) {
            // TODO Auto-generated constructor stub
            this.s = s;
        }

        @Override
        public void run() {
            // TODO Auto-generated method stub
            try {
                JsonReader reader = Json.createReader(s.getInputStream());
                JsonObject object = reader.readObject();


                String domain = object.getString("domain");

                Logger.getGlobal().info("#" + domain + "#");


                Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new FileInputStream("data" + File.separator + "dns.xml"));

//				Element e = document.getElementById(domain);
                XPath xpath = XPathFactory.newInstance().newXPath();
                Element e = (Element) xpath.evaluate("//*[@id='" + domain + "']", document, XPathConstants.NODE);

                System.out.println(e);


                if (e != null && e.getElementsByTagName("password").item(0).getFirstChild().getNodeValue().equals(Encrypt.digestSHA(object.getString("password")))) {
                    Logger.getGlobal().info("Entered");

                    Node key = e.getElementsByTagName("key").item(0);
                    Node signature = e.getElementsByTagName("signature").item(0);
                    Node file = e.getElementsByTagName("file").item(0);
                    Node rsaKey = e.getElementsByTagName("rsakey").item(0);
                    Node aesKey = e.getElementsByTagName("aeskey").item(0);

                    if (aesKey == null)
                        Logger.getGlobal().info("NULL");

                    switch (object.getString("request")) {
                        case "send":
//					key.appendChild(document.createTextNode(object.getString("key")));
                            key.getFirstChild().setNodeValue(object.getString("key"));
//					Logger.getGlobal().info(getClass().getName() + ": " + key);
//					Logger.getGlobal().info(getClass().getName() + ": " + object.getString("key"));
//					Logger.getGlobal().info(getClass().getName() + ": " + key.getFirstChild().getNodeValue());


//					signature.appendChild(document.createTextNode(object.getString("signature")));
                            signature.getFirstChild().setNodeValue(object.getString("signature"));


//					file.appendChild(document.createTextNode(object.getString("file")));
                            file.getFirstChild().setNodeValue(object.getString("file"));

                            rsaKey.getFirstChild().setNodeValue(object.getString("rsakey"));

                            aesKey.getFirstChild().setNodeValue(object.getString("aeskey"));

                            TransformerFactory transformerFactory = TransformerFactory.newInstance();
                            Transformer transformer = transformerFactory.newTransformer();
                            DOMSource source = new DOMSource(document);

                            StreamResult result = new StreamResult(new File("data" + File.separator + "dns.xml"));
                            transformer.transform(source, result);

                            Logger.getGlobal().info("Written");
                        case "receive":
                            JsonWriter writer = Json.createWriter(s.getOutputStream());
                            JsonObject obj = Json.createObjectBuilder()
                                    .add("status", "success")
                                    .add("key", key.getFirstChild().getNodeValue())
                                    .add("signature", signature.getFirstChild().getNodeValue())
                                    .add("rsakey", rsaKey.getFirstChild().getNodeValue())
                                    .add("file", file.getFirstChild().getNodeValue())
                                    .add("aeskey", aesKey.getFirstChild().getNodeValue())
                                    .build();
                            writer.writeObject(obj);
//						s.getOutputStream().flush();
                            writer.close();
                            Logger.getGlobal().info("Sent");
                    }
                } else {
                    JsonWriter writer = Json.createWriter(s.getOutputStream());
                    JsonObject obj = Json.createObjectBuilder()
                            .add("status", "failure")
                            .build();
                    writer.writeObject(obj);
//					s.getOutputStream().flush();
                    writer.close();
                }
/*				
                JsonReader reader1 = Json.createReader(new FileInputStream("data" + File.separator + "dns.json"));
				JsonObject object1 = reader1.readObject();
				JsonObject object2 = object1.getJsonObject(domain);
				
				if (object2 != null) {
					object2.put("key", object.getJsonString("key"));
					object2.put("signature", object.getJsonString("signature"));
					object2.put("file", object.getJsonString("file"));
				}
				object1.put(domain, object2);
				
				reader.close();
				JsonWriter writer = Json.createWriter(new FileOutputStream("data" + File.separator + "dns.json"));
				writer.writeObject(object1);
*/
            } catch (IOException | SAXException | ParserConfigurationException | TransformerException | XPathExpressionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}
