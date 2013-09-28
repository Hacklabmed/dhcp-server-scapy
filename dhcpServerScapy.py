#/usr/bin/env python
#-*-coding: utf-8 -*-
# Autor: @kr1shn4murt1 basado en: http://projects2009developer.files.wordpress.com/2009/03/scapy.pdf
# Referencias: http://tools.ietf.org/html/rfc2131 , http://tools.ietf.org/html/rfc2132
# Fecha: Septiembre 11 - 2013
# Dependencias: Ejecutarse con python 2.6.x o 2.7.x , tener scapy instalado en la maquina desde donde se ejecuta
# Este script actua como un servidor DHCP escuchando peticiones por la interfaz de red escogida, entrega la informacion relevante de direccionamiento ip
# a un cliente que la solicite, a mejorar esta el designar un rango de ips a entregar por ahora solo entrega 1 y agregar multihilo, luego de eso agregar
# otras funciones que sean las que ejecuten el ataque de dhcp spoofing

#Se importan las librearias de scapy, sys y netaddr
from scapy.all import *
from netaddr import * #Usada para manejar las direcciones IP
import sys #Se usa para recibir los par?metros por la linea de comandos.
import threading #Para poder tener soporte multi-hilo, cada nueva petici?n se procesar? en un nuevo hilo
import scapyConfiguration #Archivo de propiedades para utilizar scapy

#Se definen las variables con los datos de la red
ip_pool=[]
iterador = iter(ip_pool)
#Se toman las variables del archivo de propiedades
ip_Servidor=scapyConfiguration.ip_Servidor
mac_Servidor=scapyConfiguration.mac_Servidor
mascara_Subred=scapyConfiguration.mascara_Subred
puerta_Enlace=scapyConfiguration.puerta_Enlace
interfaz_A_Sniffear=scapyConfiguration.interfaz_A_Sniffear


# Se define una funcion que empieza a sniffear por la interfaz de red designada, se esniffean solo paquetes en los puertos 67 y 68 que son los que usa el servicio DHCP
def encontrar_Peticiones_Dchp():
	# De encontrar un paquetes que se este usando en ese puerto se procede a llamar otra funcion que es la que procesara los paquetes de acuerdo a su informacion
	sniff(filter='port 67 or port 68', prn=creadorHilos, iface=interfaz_A_Sniffear)

def creadorHilos(paquete): #Recibimos el paquete que nos envi? el sniffer.
	hilo = threading.Thread(target=procesar_Peticiones_Dhcp, args=(paquete,)) #Creamos un nuevo hilo que toma como argumento el paquete enviado.
	hilo.daemon = True #Se usa para permitir que la aplicaci?n salga incluso si el hilo no ha acabado.
	hilo.start() #Inicia la ejecuci?n del hilo
	#hilo.join() #Se debe unir si se va a trabajar con informaci?n de los hilos por fuera del hilo, de lo contrario no hace falta.

# Esta funcion es la que procesa los paquetes teniendo en cuenta si son de tipo discover o request y de acuerdo a esto se crea y se envia un paquete como respuesta
# a dichas solicitudes
def procesar_Peticiones_Dhcp(paquete):
	# Se verifica que el paquete tenga la capa DHCP
	if paquete[DHCP]:

		#Se verifica si es un paquete tipo request DHCP message-type = discover (1)
		# para luego responder con un paquete tipo offer
		if paquete[DHCP].options[0][1]== 1:
		
			ip_cliente = str(retornaSiguienteIP()) #Tomamos una IP de la lista para darsela al cliente
			if ip_cliente == "fin": #Si se acaban las direcciones, salir de la funci?n. TODO: Tomar una mejor decisi?n sobre que hacer si no hay direcciones.
				print "No hay m?s direcciones IP en el rango ingresado."
				return 

			print '\tDetectado paquete DHCP tipo discover, se creara y enviara un paquete DHCP Offer como respuesta'
			
			print 'mac del cliente:', paquete[Ether].src
			
			# Se crea el paquete DHCP Offer con la informacion requerida, el campo xid de la capa bootp se toma del paquete que lo solicita, ya que el paquete 
			#respuesta debe tener el mismo numero
			capa_3_Ethernet=Ether(src=mac_Servidor,dst=paquete[Ether].src)
			capa_4_Ip=IP(src=ip_Servidor,dst=ip_cliente)
			capa_5_UDP=UDP(sport=67,dport=68)
			capa_6_BOOTP=BOOTP(op=2,yiaddr=ip_cliente,siaddr=ip_Servidor,giaddr='0.0.0.0',xid=paquete[BOOTP].xid)
			capa_7_DHCP=DHCP(options=[('message-type','offer'),('subnet_mask','255.255.255.0'),('server_id',ip_Servidor),('lease_time',1800),('domain','localdomain'),('name_server',ip_Servidor),('end')])

			# Se apilan las capas antes creadas con el separador '/' para crear el paquete DHCP tipo offer
			paquete_Offer=capa_3_Ethernet/capa_4_Ip/capa_5_UDP/capa_6_BOOTP/capa_7_DHCP

			# Se envia el paquete al cliente que lo solicito
			sendp(paquete_Offer)
			print 'Paquete DHCP Offer enviado: ',paquete_Offer.summary()
		#Se verifica si es un paquete tipo request DHCP message-type = request (3)
		# para luego responder con un paquete tipo ACK
		if paquete[DHCP].options[0][1]== 3:
			print '\tDetectado paquete DHCP tipo request, se creara y enviara un paquete DHCP ack como respuesta'
			print 'mac del cliente:', paquete[Ether].src
			#Se obtiene la ip del cliente a traves de la opcion request_addr
			ip_cliente=paquete[DHCP].options[2][1]
			# Se crea el paquete ack, tiene los mismos datos que el paquete anterior solo que en la capa DHCP el campo message-type cambia el valor de offer por ack
			paquete_ACK=Ether(src=mac_Servidor,dst=paquete[Ether].src)/IP(src=ip_Servidor,dst=ip_cliente)/UDP(sport=67,dport=68)/BOOTP(op=2,yiaddr=ip_cliente,siaddr=ip_Servidor,giaddr='0.0.0.0',xid=paquete[BOOTP].xid)/DHCP(options=[('message-type','ack'),('subnet_mask','255.255.255.0'),('server_id',ip_Servidor),('lease_time',1800),('domain','localdomain'),('name_server',ip_Servidor),('end')])
			sendp(paquete_ACK)
			print 'Paquete DHCP ACK enviado: ',paquete_ACK.summary()
	
	print 'procesado', paquete.summary()

#Organiza las direcciones que se le asignar?n a los usuarios
def preparaDirecciones(rango): 
	#Se definen las variables globales para su uso posterior
	global ip_pool
	global iterador
	x = rango.find("-")
	try:	
		if x != -1: #Si es un rango definido por medio de '-' tiene una estructura diferente.
			ip_pool = list(iter_iprange(rango[0:x],rango[x+1:]))
		else: #La estructura x.x.x.x/y es soportada por este constructor.
			ip_pool = list(IPNetwork(rango))
	except (AddrFormatError, ValueError): #Si tenemos problemas....
		print "Error, el rango ingresado no es v?lido... Saliendo"
		exit()		
	iterador = iter(ip_pool)# Creamos un iterador con los objetos
	
def retornaSiguienteIP(): #Itera la lista, cuando se acaba, devuelve "fin"
	try:
		return iterador.next()
	except StopIteration:
		return "fin"

if len(sys.argv) != 2: 
	print "Error, n?mero de par?metros incorrecto, debe ingresar el rango de IPs en formato x.x.x.x/24 o x.x.x.x-y.y.y.y"
	print "Ej: ./"+sys.argv[0]+" 192.168.0.1/24"
	print "Ej2: ./"+sys.argv[0]+" 10.0.0.1-10.0.1.255"
	exit()

#Llenamos la lista con el rango que nos ingres? el usuario y preparamos el iterador
preparaDirecciones(sys.argv[1]) 
# Se llama a la funcion de sniffeo principal para iniciar la ejecucion del script
encontrar_Peticiones_Dchp()
