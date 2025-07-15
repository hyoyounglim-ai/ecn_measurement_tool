echo "Starting ECN traceroute measurement using input file : $1";
mkdir traceroute

fx=`cat $1`
for filename in $fx
do
fx2=`echo $filename | cut -f2 -d ','`
echo "starting the file: $fx2"
sudo ./venv/bin/python traceroute_only.py $fx2
pkill -9 python
echo "finished"
done

echo "Finishing the traceroute measurement, Thank you."