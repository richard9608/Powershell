Josh port-sec commands


# Script to generate commands for disabling port security on a range of interfaces
# and copying them to the clipboard for easy pasting into a terminal.   
#--------------------------------------------------------------------------------------------

$a = ("Gi1/0/1
Gi1/0/2
Gi1/0/3
Gi1/0/4
Gi1/0/5
Gi1/0/6
Gi1/0/7
Gi1/0/8
Gi1/0/9
Gi1/0/10
Gi1/0/11
Gi1/0/12
Gi1/0/13
Gi1/0/14
Gi1/0/15
Gi1/0/16
Gi1/0/17
Gi1/0/18
Gi1/0/19
Gi1/0/20
Gi1/0/21
Gi1/0/22
Gi1/0/23
Gi1/0/24
Gi1/0/25
Gi1/0/26
Gi1/0/27
Gi1/0/28
Gi1/0/29
Gi1/0/30
Gi1/0/31
Gi1/0/32
Gi1/0/33
Gi1/0/34
Gi1/0/35
Gi1/0/36
Gi1/0/37
Gi1/0/38
Gi1/0/39").split()

$a|%{"int $_
no switchport port-sec"}|Set-Clipboard

#--------------------------------------------------------------------------------------------
Configure terminal
int Gi1/0/1
no switchport port-sec
int Gi1/0/2
no switchport port-sec
int Gi1/0/3
no switchport port-sec
int Gi1/0/4
no switchport port-sec
int Gi1/0/5
no switchport port-sec
int Gi1/0/6
no switchport port-sec
int Gi1/0/7
no switchport port-sec
int Gi1/0/8
no switchport port-sec
int Gi1/0/9
no switchport port-sec
int Gi1/0/10
no switchport port-sec
int Gi1/0/11
no switchport port-sec
int Gi1/0/12
no switchport port-sec
int Gi1/0/13
no switchport port-sec
int Gi1/0/14
no switchport port-sec
int Gi1/0/15
no switchport port-sec
int Gi1/0/16
no switchport port-sec
int Gi1/0/17
no switchport port-sec
int Gi1/0/18
no switchport port-sec
int Gi1/0/19
no switchport port-sec
int Gi1/0/20
no switchport port-sec
int Gi1/0/21
no switchport port-sec
int Gi1/0/22
no switchport port-sec
int Gi1/0/23
no switchport port-sec
int Gi1/0/24
no switchport port-sec
int Gi1/0/25
no switchport port-sec
int Gi1/0/26
no switchport port-sec
int Gi1/0/27
no switchport port-sec
int Gi1/0/28
no switchport port-sec
int Gi1/0/29
no switchport port-sec
int Gi1/0/30
no switchport port-sec
int Gi1/0/31
no switchport port-sec
int Gi1/0/32
no switchport port-sec
int Gi1/0/33
no switchport port-sec
int Gi1/0/34
no switchport port-sec
int Gi1/0/35
no switchport port-sec
int Gi1/0/36
no switchport port-sec
int Gi1/0/37
no switchport port-sec
int Gi1/0/38
no switchport port-sec
int Gi1/0/39
no switchport port-sec
do clear port-sec all


#--------------------------------------------------------------------------------------------

ctrl + c #will take back to pri




 