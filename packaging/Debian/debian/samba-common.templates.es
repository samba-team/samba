Template: samba-common/do_debconf
Type: boolean
Default: true
Description: Configure smb.conf through debconf?
 The rest of the configuration of Samba deals with questions that affect
 parameters in /etc/samba/smb.conf, which is the file used to configure the
 Samba programs (nmbd and smbd.) If you want to be asked just a few
 questions then select "Yes" and continue with the configuration. If you
 want to have full control, select "No" and configure your smb.conf
 manually or through SWAT.
Description-es: ¿Configurar smb.conf mediante debconf?
 El resto de la configuración de Samba trata sobre cuestiones que afectan
 al contenido de /etc/samba/smb.conf, que es el fichero utilizado para
 configurar los programas de Samba (nmbd y smbd). Si desea responder a las
 preguntas, elija "Sí" y continuará con la configuración. Si quiere
 tener control total, escoja "No" y configure smb.conf manualmente o con
 SWAT.

Template: samba-common/workgroup
Type: string
Description: Workgroup/Domain Name?
 This controls what workgroup your server will appear to be in when queried
 by clients. Note that this parameter also controls the Domain name used
 with the security=domain setting.
Description-es: Nombre del dominio o del grupo de trabajo.
 Es el grupo de trabajo en el que aparecerá su servidor cuando se lo
 pregunten los clientes de la red. Este parámetro también controla el
 nombre de dominio que se usa con la configuración security=domain.

Template: samba-common/encrypt_passwords
Type: boolean
Default: true
Description: Use password encryption?
 Recent Windows clients communicate with SMB servers using encrypted
 passwords. If you want to use clear text passwords you will need to change
 a parameter in your Windows registry. It is recommended that you use
 encrypted passwords. If you do, make sure you have a valid
 /etc/samba/smbpasswd file and that you set passwords in there for each
 user using the smbpasswd command.
Description-es: ¿Utilizar contraseñas cifradas?
 Los clientes Windows más modernos se comunican con los servidores SMB
 utilizando contraseñas cifradas. Si quiere usar contraseñas en texto
 plano, tendrá que cambiar un parámetro en el registro de Windows. Es muy
 recomendable usar cifrado en las contraseñas. Si elige hacerlo, compruebe
 que tiene un fichero /etc/samba/smbpasswd válido y que ha puesto las
 contraseñas con el programa smbpasswd.
