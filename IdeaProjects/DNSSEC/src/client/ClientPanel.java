package client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class ClientPanel extends JPanel {
    protected JRadioButton jrbSend = new JRadioButton("Send");
    protected JRadioButton jrbReceive = new JRadioButton("Receive");
    protected JButton jbNext = new JButton("Next");
    protected JRadioButton jrbMsg = new JRadioButton("Message");
    protected JRadioButton jrbFile = new JRadioButton("File");
    protected JButton jbNext1 = new JButton("Next");
    protected JButton jbFile = new JButton("Select File");
    protected JLabel jlFile = new JLabel("No file selected");
    protected JButton jbKey = new JButton("Generate key");
    //	protected JLabel jlKey = new JLabel("No keys yet");
    protected JTextField jlKey = new JTextField("No keys yet");
    protected JButton jbSignature = new JButton("Generate Signature");
    //	protected JLabel jlSignature = new JLabel("No Signature yet");
    protected JTextField jlSignature = new JTextField("No Signature yet");
    protected JButton btnSend = new JButton("Send");
    protected JButton btnReceive = new JButton("Receive");
    protected JTextField jtfKey = new JTextField(20);
    protected JTextField jtfSignature = new JTextField(20);
    protected JButton btnValidate = new JButton("Validate");

    private File file;
    private PrivateKey priv;
    private PublicKey pub;
    private byte[] realSig;

    private byte[] data;
    private JLabel jlMsg = new JLabel("Enter a message");
    private JTextField jtfMsg = new JTextField(20);
    private JButton jbKey1 = new JButton("Generate key");
    //	private JLabel jlKey1 = new JLabel("No key yet");
    private JTextField jlKey1 = new JTextField("No key yet");
    private JButton jbSignature1 = new JButton("Generate signature");
    //	private JLabel jlSignature1 = new JLabel("No signature yet");
    private JTextField jlSignature1 = new JTextField("No signature yet");
    private JButton btnSend1 = new JButton("Send");
    private JButton jbRSA = new JButton("RSA keys");
    private JTextField jtfRSA = new JTextField(20);
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private byte[] encryptData;
    private JButton jbRSAMsg = new JButton("algorithms.Encrypt Msg");
    private JTextField jtfRSAMsg = new JTextField(20);

    private JButton jbRSA1 = new JButton("RSA keys");
    private JTextField jtfRSA1 = new JTextField(20);

    private JButton jbRSAMsg1 = new JButton("algorithms.Encrypt Msg");
    private JTextField jtfRSAMsg1 = new JTextField(20);


    private JLabel jlFileReceived = new JLabel("File received");
    private JTextArea jtfFileReceived = new JTextArea(5, 20);

    private SecretKey secretKey;
    private byte[] encryptFileData;

    {
//		jlKey = new JTextArea(20, 5);

    }


    public ClientPanel() {
        // TODO Auto-generated constructor stub
        CardLayout layout = new CardLayout(50, 50);
        setLayout(layout);

		/*----------Card 1--------------------------*/

        JPanel card1 = new JPanel();
        card1.setLayout(new BorderLayout(25, 25));

        card1.add(new JLabel("What would you like to do?"), BorderLayout.NORTH);

        ButtonGroup group = new ButtonGroup();
        group.add(jrbSend);
        group.add(jrbReceive);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(2, 1));

        buttonPanel.add(jrbSend);
        buttonPanel.add(jrbReceive);

        card1.add(buttonPanel, BorderLayout.CENTER);

        card1.add(jbNext, BorderLayout.SOUTH);
        jbNext.addActionListener(e -> {
            if (jrbSend.isSelected())
                layout.show(ClientPanel.this, "Message File");
            else if (jrbReceive.isSelected())
                layout.show(ClientPanel.this, "Receive");
        });

        add(card1, "Send Receive");

		/*----------Card 2--------------------------*/

        JPanel card2 = new JPanel();
        card2.setLayout(new BorderLayout(25, 25));

        card2.add(new JLabel("What would you like to send?"), BorderLayout.NORTH);

        ButtonGroup group1 = new ButtonGroup();
        group1.add(jrbMsg);
        group1.add(jrbFile);

        JPanel buttonPanel1 = new JPanel();
        buttonPanel1.setLayout(new GridLayout(2, 1));

        buttonPanel1.add(jrbMsg);
        buttonPanel1.add(jrbFile);

        card2.add(jbNext1, BorderLayout.SOUTH);
        jbNext1.addActionListener(e -> {
            if (jrbFile.isSelected())
                layout.show(ClientPanel.this, "File");
            else if (jrbMsg.isSelected())
                layout.show(ClientPanel.this, "Message");
        });
        card2.add(buttonPanel1, BorderLayout.CENTER);

        add(card2, "Message File");

		/*----------Card 3--------------------------*/

        JPanel card3 = new JPanel();
        card3.setLayout(new GridLayout(6, 1, 0, 15));

        JPanel filePanel = new JPanel();
        filePanel.setLayout(new GridLayout(1, 2, 15, 0));

        filePanel.add(jbFile);
        filePanel.add(jlFile);

        jbFile.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.showOpenDialog(ClientPanel.this);

            file = chooser.getSelectedFile();
            jlFile.setText(file.getAbsolutePath());
            jlFile.setToolTipText(file.getAbsolutePath());
        });

        card3.add(filePanel);

        JPanel keyPanel = new JPanel();

        keyPanel.setLayout(new GridLayout(1, 2, 15, 0));
        keyPanel.add(jbKey);
        keyPanel.add(jlKey);

        jbKey.addActionListener(e -> {
            if (file == null) {
                JOptionPane.showMessageDialog(ClientPanel.this, "Please select file first", "No file selected", JOptionPane.ERROR_MESSAGE);
            } else {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                    SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                    keyGen.initialize(1024, random);
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();
                    jlKey.setText("Private key: " + new String(priv.getEncoded()) + "\nPublic key: " + new String(pub.getEncoded()));
//					jlKey.setToolTipText("Private key: " + new String(priv.getEncoded()) + "\nPublic key: " + new String(pub.getEncoded()));
                } catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        });

        card3.add(keyPanel);

        JPanel signaturePanel = new JPanel();

        signaturePanel.setLayout(new GridLayout(1, 2, 15, 0));
        signaturePanel.add(jbSignature);
        signaturePanel.add(jlSignature);

        jbSignature.addActionListener(e -> {
            try {
                Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
                dsa.initSign(priv);
                FileInputStream fis = new FileInputStream(file);
                BufferedInputStream bufin = new BufferedInputStream(fis);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = bufin.read(buffer)) >= 0) {
                    dsa.update(buffer, 0, len);
                }
                ;
                bufin.close();
                realSig = dsa.sign();
                jlSignature.setText(new String(realSig));
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });

        card3.add(signaturePanel);

        JPanel rsaPanel = new JPanel();
        rsaPanel.setLayout(new GridLayout(1, 2, 15, 0));

        rsaPanel.add(jbRSA);
        rsaPanel.add(jtfRSA);

        jbRSA.addActionListener(e -> {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();

                jtfRSA.setText("private: " + new String(privateKey.getEncoded()) + ";public: " + new String(privateKey.getEncoded()));
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });

        card3.add(rsaPanel);

        JPanel rsaMsgPanel = new JPanel();
        rsaMsgPanel.setLayout(new GridLayout(1, 2, 15, 0));
        rsaMsgPanel.add(jbRSAMsg);
        rsaMsgPanel.add(jtfRSAMsg);

        card3.add(rsaMsgPanel);

        jbRSAMsg.addActionListener(e -> {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128);
                secretKey = keyGenerator.generateKey();

                Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());

                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                ByteArrayOutputStream out = new ByteArrayOutputStream();

                InputStream in = new FileInputStream(file);
                byte[] bs = new byte[1024];
                int count;
                while ((count = in.read(bs)) > 0) {
                    out.write(bs, 0, count);
                }
                in.close();
                out.close();

//				encryptFileData = cipher.doFinal(out.toByteArray());
                Cipher aesCipher = Cipher.getInstance("AES");
                aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                encryptFileData = aesCipher.doFinal(out.toByteArray());

                encryptData = cipher.doFinal(secretKey.getEncoded());
                jtfRSAMsg.setText(new String(encryptData));
                Logger.getGlobal().info(new String(encryptData));
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        });


        card3.add(btnSend);

        btnSend.addActionListener(e -> {
            String domain = JOptionPane.showInputDialog(ClientPanel.this, "Enter domain name");

            JPanel panel = new JPanel();
            JLabel label = new JLabel("Enter a password:");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "The title",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[1]);

            String password = null;
            if (option == 0) // pressing OK button
            {
                password = new String(pass.getPassword());
                System.out.println("Your password is: " + new String(password));

            }

//			String password = JOptionPane.showInputDialog(client.ClientPanel.this, "Enter password");
            try {
                JsonReader reader = Json.createReader(new FileInputStream("data" + File.separator + "server.json"));
                JsonObject object = reader.readObject();
                Socket socket = new Socket(InetAddress.getByName(object.getString("ip")), object.getInt("port"));
                /*
                ByteArrayOutputStream out = new ByteArrayOutputStream();
				
				InputStream in = new FileInputStream(file);
				byte[] bs = new byte[1024];
				int count;
				while ((count = in.read(bs)) > 0) {
					out.write(bs, 0, count);
				}
				in.close();
				out.close();
				*/
//				Logger.getGlobal().info(Base64.getEncoder().encodeToString(pub.getEncoded()));
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                JsonWriter writer = Json.createWriter(baos);
                JsonObject obj = Json.createObjectBuilder()
                        .add("request", "send")
                        .add("domain", domain)
                        .add("password", password)
                        .add("key", Base64.getEncoder().encodeToString(pub.getEncoded()))
                        .add("signature", Base64.getEncoder().encodeToString(realSig))
//						.add("file", out.toString())
                        .add("rsakey", Base64.getEncoder().encodeToString(privateKey.getEncoded()))
                        .add("aeskey", Base64.getEncoder().encodeToString(encryptData))
                        .add("file", Base64.getEncoder().encodeToString(encryptFileData))
                        .build();
                writer.writeObject(obj);
                writer.close();

                OutputStream out1 = socket.getOutputStream();
                out1.write(baos.toByteArray());
                out1.flush();

                JsonReader reader1 = Json.createReader(socket.getInputStream());
                JsonObject obj1 = reader1.readObject();
                if (obj1.getString("status").equals("failure"))
                    JOptionPane.showMessageDialog(ClientPanel.this, "Invalid domain or password");
                else
                    JOptionPane.showMessageDialog(ClientPanel.this, "Upload successful");
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });

        add(card3, "File");
		
		/* ------------------Card 4----------------------*/

        JPanel card4 = new JPanel();
        card4.setLayout(new BoxLayout(card4, BoxLayout.Y_AXIS));
        card4.add(new JLabel("Receive public key, signature and file"));
        card4.add(btnReceive);

        btnReceive.addActionListener(e -> {
            String domain = JOptionPane.showInputDialog(ClientPanel.this, "Enter domain name");

            JPanel panel = new JPanel();
            JLabel label = new JLabel("Enter a password:");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "The title",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[1]);

            String password = null;
            if (option == 0) // pressing OK button
            {
                password = new String(pass.getPassword());
                System.out.println("Your password is: " + new String(password));

            }

//			String password = JOptionPane.showInputDialog(client.ClientPanel.this, "Enter password");
            try {
                JsonReader reader = Json.createReader(new FileInputStream("data" + File.separator + "server.json"));
                JsonObject object = reader.readObject();
                Socket socket = new Socket(InetAddress.getByName(object.getString("ip")), object.getInt("port"));
/*				
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				
				InputStream in = new FileInputStream(file);
				byte[] bs = new byte[1024];
				int count;
				while ((count = in.read(bs)) > 0) {
					out.write(bs, 0, count);
				}
				in.close();
				out.close();
*/
//				Logger.getGlobal().info(new String(pub.getEncoded()));

//				JsonWriter writer = Json.createWriter(socket.getOutputStream());
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                JsonWriter writer = Json.createWriter(out);
                JsonObject obj = Json.createObjectBuilder()
                        .add("request", "receive")
                        .add("domain", domain)
                        .add("password", password)
                        .build();
                writer.writeObject(obj);
                writer.close();
                OutputStream out1 = socket.getOutputStream();
                out1.write(out.toByteArray());
                out1.flush();

                JsonReader reader1 = Json.createReader(socket.getInputStream());
                JsonObject obj1 = reader1.readObject();

//				Logger.getGlobal().info(obj1.getString("key"));

                if (obj1.getString("status").equals("failure")) {
                    JOptionPane.showMessageDialog(ClientPanel.this, "Invalid domain or password");
                    return;
                }

                byte[] decodeKey = Base64.getDecoder().decode(obj1.getString("key"));
                realSig = Base64.getDecoder().decode(obj1.getString("signature"));

                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodeKey);
                KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
                pub = keyFactory.generatePublic(pubKeySpec);

                String key1 = new String(decodeKey);
                String signature1 = new String(realSig);

                byte[] aesEncryptedKey = Base64.getDecoder().decode(obj1.getString("aeskey"));

                Logger.getGlobal().info("496: " + obj1.getString("aeskey"));

                Logger.getGlobal().info(obj1.getString("rsakey"));

                byte[] decodeKey1 = Base64.getDecoder().decode(obj1.getString("rsakey"));
                PKCS8EncodedKeySpec priKeySpec1 = new PKCS8EncodedKeySpec(decodeKey1);
                KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
                privateKey = keyFactory1.generatePrivate(priKeySpec1);


//				Logger.getGlobal().info(new String(privateKey.getEncoded()));
                byte[] decodeFile = Base64.getDecoder().decode(obj1.getString("file"));

                Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, privateKey);

//				data = cipher.doFinal(decodeFile);
                byte[] aesKey = cipher.doFinal(aesEncryptedKey);
                secretKey = new SecretKeySpec(aesKey, 0, aesKey.length, "AES");

                Cipher cipher2 = Cipher.getInstance("AES");
                cipher2.init(Cipher.DECRYPT_MODE, secretKey);

                data = cipher2.doFinal(decodeFile);

//				Logger.getGlobal().info(new String(data));

//				jtfFileReceived.setText(new String(data));

                jtfKey.setText("Your key: " + key1);
                jtfSignature.setText("Your signature: " + signature1);

//				Logger.getGlobal().info(obj1.getString("key"));
            } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });


//		jtfKey.setEditable(false);
        jtfKey.setText("Your Key: ");
        card4.add(jtfKey);
//		jtfSignature.setEditable(false);
        jtfSignature.setText("Your Signature: ");
        card4.add(jtfSignature);
        card4.add(new JLabel("Validate signature"));

        card4.add(new JScrollPane(jtfFileReceived));

        card4.add(btnValidate);


        btnValidate.addActionListener(e -> {
            try {
                Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
                sig.initVerify(pub);
                sig.update(data);
                boolean verifies = sig.verify(realSig);
                if (verifies) {
                    JOptionPane.showMessageDialog(ClientPanel.this, "Success");
                    jtfFileReceived.setText(new String(data));
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });


        add(card4, "Receive");
		
		/*--------------------------Card 5----------------------------*/

        JPanel card5 = new JPanel();
        card5.setLayout(new GridLayout(6, 1, 0, 15));

        JPanel msgPanel = new JPanel();
        msgPanel.setLayout(new GridLayout(1, 2, 15, 0));

        msgPanel.add(jlMsg);
        msgPanel.add(jtfMsg);

        card5.add(msgPanel);

        JPanel keyPanel1 = new JPanel();

        keyPanel1.setLayout(new GridLayout(1, 2, 15, 0));
        keyPanel1.add(jbKey1);
        keyPanel1.add(jlKey1);

        jbKey1.addActionListener(e -> {
            if (jtfMsg.getText() == null || jtfMsg.getText().equals("")) {
                JOptionPane.showMessageDialog(ClientPanel.this, "Please type some text", "Empty text", JOptionPane.ERROR_MESSAGE);
            } else {
                try {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                    SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                    keyGen.initialize(1024, random);
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();
                    jlKey1.setText("Private key: " + new String(priv.getEncoded()) + "\nPublic key: " + new String(pub.getEncoded()));
                } catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        });

        card5.add(keyPanel1);

        JPanel signaturePanel1 = new JPanel();

        signaturePanel1.setLayout(new GridLayout(1, 2, 15, 0));
        signaturePanel1.add(jbSignature1);
        signaturePanel1.add(jlSignature1);

        jbSignature1.addActionListener(e -> {
            try {
                Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
                dsa.initSign(priv);
                dsa.update(jtfMsg.getText().getBytes());
                realSig = dsa.sign();
                jlSignature1.setText(new String(realSig));
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });

        card5.add(signaturePanel1);

        JPanel rsaPanel1 = new JPanel();
        rsaPanel1.setLayout(new GridLayout(1, 2, 15, 0));

        rsaPanel1.add(jbRSA1);
        rsaPanel1.add(jtfRSA1);

        jbRSA1.addActionListener(e -> {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();

                jtfRSA1.setText("private: " + new String(privateKey.getEncoded()) + ";public: " + new String(privateKey.getEncoded()));
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });

        card5.add(rsaPanel1);

        JPanel rsaMsgPanel1 = new JPanel();
        rsaMsgPanel1.setLayout(new GridLayout(1, 2, 15, 0));
        rsaMsgPanel1.add(jbRSAMsg1);
        rsaMsgPanel1.add(jtfRSAMsg1);

        card5.add(rsaMsgPanel1);

        jbRSAMsg1.addActionListener(e -> {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                secretKey = kg.generateKey();

                Cipher aesCipher = Cipher.getInstance("AES");

                aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

                encryptData = aesCipher.doFinal(jtfMsg.getText().getBytes());
                jtfRSAMsg1.setText(new String(encryptData));
                Logger.getGlobal().info(new String(encryptData));
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        });

        card5.add(btnSend1);

        btnSend1.addActionListener(e -> {
            String domain = JOptionPane.showInputDialog(ClientPanel.this, "Enter domain name");

            JPanel panel = new JPanel();
            JLabel label = new JLabel("Enter a password:");
            JPasswordField pass = new JPasswordField(10);
            panel.add(label);
            panel.add(pass);
            String[] options = new String[]{"OK", "Cancel"};
            int option = JOptionPane.showOptionDialog(null, panel, "The title",
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[1]);

            String password = null;
            if (option == 0) // pressing OK button
            {
                password = new String(pass.getPassword());
                System.out.println("Your password is: " + new String(password));

            }

//			String password = JOptionPane.showInputDialog(client.ClientPanel.this, "Enter domain name");

            try {
                Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());

                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                byte[] aesEncyptedKey = cipher.doFinal(secretKey.getEncoded());

                JsonReader reader = Json.createReader(new FileInputStream("data" + File.separator + "server.json"));
                JsonObject object = reader.readObject();
                Socket socket = new Socket(InetAddress.getByName(object.getString("ip")), object.getInt("port"));

//				Logger.getGlobal().info(Base64.getEncoder().encodeToString(pub.getEncoded()));

                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                JsonWriter writer = Json.createWriter(baos);
                JsonObject obj = Json.createObjectBuilder()
                        .add("request", "send")
                        .add("domain", domain)
                        .add("password", password)
                        .add("key", Base64.getEncoder().encodeToString(pub.getEncoded()))
                        .add("signature", Base64.getEncoder().encodeToString(realSig))
                        .add("rsakey", Base64.getEncoder().encodeToString(privateKey.getEncoded()))
                        .add("file", Base64.getEncoder().encodeToString(encryptData))
                        .add("aeskey", Base64.getEncoder().encodeToString(aesEncyptedKey))
                        .build();
                writer.writeObject(obj);
                writer.close();

                OutputStream out1 = socket.getOutputStream();
                out1.write(baos.toByteArray());
                out1.flush();

                JsonReader reader1 = Json.createReader(socket.getInputStream());
                JsonObject obj1 = reader1.readObject();
                if (obj1.getString("status").equals("failure"))
                    JOptionPane.showMessageDialog(ClientPanel.this, "Invalid domain or password");
                else
                    JOptionPane.showMessageDialog(ClientPanel.this, "Upload successful");
            } catch (IOException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (NoSuchAlgorithmException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (NoSuchPaddingException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (InvalidKeyException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (IllegalBlockSizeException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (BadPaddingException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        });

        add(card5, "Message");

        layout.show(this, "Send Receive");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                // TODO Auto-generated method stub
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
                        | UnsupportedLookAndFeelException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                JFrame frame = new JFrame("");
                frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
                frame.setContentPane(new ClientPanel());

                frame.pack();

                Toolkit t = Toolkit.getDefaultToolkit();
                Dimension d = t.getScreenSize();

                frame.setLocation((d.width - frame.getWidth()) / 2, (d.height - frame.getHeight()) / 2);
                frame.setVisible(true);
            }
        });


    }
}
