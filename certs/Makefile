deploy: truststore.p12 keycloak.p12 app.p12 server.p12
	cp app.p12 truststore.p12 ../client/src/main/resources
	cp server.p12 truststore.p12 ../server/src/main/resources
	cp keycloak.p12 truststore.p12 ../

app.p12: app
	openssl pkcs12 -export -in app/app.pem -inkey app/app-key.pem -name app -out app.p12 -passout pass:password

keycloak.p12: keycloak
	openssl pkcs12 -export -in keycloak/keycloak.pem -inkey keycloak/keycloak-key.pem -name keycloak -out keycloak.p12 -passout pass:password

server.p12: server
	openssl pkcs12 -export -in server/server.pem -inkey server/server-key.pem -name server -out server.p12 -passout pass:password

truststore.p12: ca
	keytool -import -keystore truststore.p12 -storetype PKCS12 -trustcacerts -alias root -file ca/ca.pem -storepass password

ca:
	mkdir ca
	cfssl gencert -initca ca-csr.json | cfssljson -bare ca/ca -

app: ca
	mkdir app
	cfssl gencert -ca ca/ca.pem -ca-key ca/ca-key.pem -config ca-config.json \
		-profile www app-csr.json | cfssljson -bare app/app -

keycloak: ca
	mkdir keycloak
	cfssl gencert -ca ca/ca.pem -ca-key ca/ca-key.pem -config ca-config.json \
		-profile www keycloak-csr.json | cfssljson -bare keycloak/keycloak - 

server: ca
	mkdir server
	cfssl gencert -ca ca/ca.pem -ca-key ca/ca-key.pem -config ca-config.json \
		-profile www server-csr.json | cfssljson -bare server/server - 

clean:
	rm -fr ca app keycloak server
	rm *.p12
