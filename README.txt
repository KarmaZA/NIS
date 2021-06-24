Network and Internetwork Security Assigment
===========================================
1) Configuring IntelliJ
Welcome to our secure messaging network. We have configured our code over IntelliJ! So here are some steps on how to run it.
You need to have BouncyCastle set up in order to run our code.
Download the bcpg-jdk15on-169.jar from https://www.bouncycastle.org/latest_releases.html and place it in your Java Runtime Environment in Java\jre1.8.0_261\lib\ext. Then you need to configure the Java security class in Java\jre1.8.0_261\lib\security and add a line to java.security. The line is
security.provider.n=org.bouncycastle.jce.provider.BouncyCastleProvider
add this under all your security providers.

Then we need to configure bouncy castle within IntelliJ. Open the project file NIS in IntelliJ and add bouncy castle to the External Libraries. Do this by clicking "File" and then Project Sturcture.
Go to "Modules" and and click on dependencies which is next to "Sources" and "Paths". Then click on the plus sign and locate to your bcprov file is and add it as a dependency and click "Apply".
See "IntelliJ Dependencies.PNG" for clarity if you have any trouble with this.


2) Running the program
Firstly run the AuthenticationServer.java within IntelliJ. Once that is running, run Bob.java. You need to run Bob and Authentication server on the same computer as they run over localhost, however Alice can be run over localhost or another IP.
Once Bob is bobbing, you can run Alice.java. Alice will ask for IP address of the computer you wish to connect to. You can enter in the other IP or simply write "localhost". Once this is done the connection would have been established and you can begin messaging. 
To send a message simply type in the message and it will be sent. If you wish to upload an image, type "upload" then press enter. Then type in the name of the file you wish to transfer, we used "link.jpeg" and press enter. 
Then you can type in a string for the image caption and press enter. Then the image will be sent over to the other address. Bob and Alice can message each other and exchange images. Happy chatting in a safe secure manner!
