echo "Starting ECN traceroute measurement using input file : $1";
mkdir traceroute

fx=`cat $1`
for filename in $fx
do
fx2=`echo $filename | cut -f2 -d ','`
echo "starting the file: $fx2"
python3 traceroute_only.py $fx2
pkill -9 python3
echo "finished"
done

echo "Finishing the traceroute measurement, Thank you."