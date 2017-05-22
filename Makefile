all:
	javac Test.java -cp message.jar

run:
	java -cp "message.jar:./" Test
