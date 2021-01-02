gcc ./AES_GenPowerProfile.c -o AES_GenPowerProfile -lncurses
for i in $(seq 0 15); do 
    # OUT=(`./AES_GenPowerProfile $i`)
	OUT=`./AES_GenPowerProfile $i`
	if [ $i == 0 ] 
	then 
		echo "True Round Key:    $OUT"
		printf "Extracted Key HW:  "
	fi 
	# echo "Exp#$i - extracting byte #$i of the key"; 
	# echo "${OUT[${i}]}"
	EX=`python ./part1.py HammingWeight | cut -c3-`
	printf "%02s " $EX
done
printf "\n"
for i in $(seq 0 15); do 
    ./AES_GenPowerProfile $i > /dev/null
    if [ $i == 0 ] 
	then 
		printf "Extracted Key HD:  "
    fi
    EX=`python ./part1.py HammingDistance | cut -c3-`
	printf "%02s " $EX
done
printf "\n"