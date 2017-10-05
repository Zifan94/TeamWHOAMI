#!/bin/bash
case $1 in
    "update_pg" )
		pip install git+https://github.com/CrimsonVista/Playground3.git@master --upgrade
		exit
    ;;

    "run" )
        case $2 in
            "test" )
                python3 -m netsec_fall2017.lab2.lab2_test.UnitTest
                exit
            ;;

            "server" )
                python3 -m netsec_fall2017.lab2.lab2_test.VerificationCodeServerProtocol
                exit
            ;;

            "client" )
                python3 -m netsec_fall2017.lab2.lab2_test.VerificationCodeClientProtocol
                exit
            ;;

            * ) echo "Incorrect args"
        esac
        exit
    ;;

    * ) echo "Incorrect args"

esac
