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

2) Configuring the IP
Next you need to configure the IP address to match the computer you want to send to. To do this find the IP of your computer and the computer and make sure the IP within Bob matches Alice's IP and vice versa.
If you wish to run both on the same computer simply use localhost.

3) Running the program
Firstly run the AuthenticationServer.java within IntelliJ. Once that is running, run Bob.java. You need to run Bob and Authentication server on the same computer as they run over localhost.
Once Bob is bobbing, you can run Alice.java and they will be able to message one another and send images.
