echo "Starting ECN web-server measurement using input file : filelist_server.txt";
mkdir ecnserver
# fx=`cat filelist_server.txt`
# for filename in $fx
# do
# echo "$filename"
# fx2=`cat $filename`
# for filename_2 in $fx2
# do
# fx3=`echo $filename_2 | cut -f2 -d ','`
# echo "$fx3"
# python3 ecn.py $fx3
# pkill -9 python3
# done
# done

fx=`cat filelist_server.txt`
for filename in $fx
do
echo "$filename"
fx2=`cat $filename`
for filename_2 in $fx2
do
fx3=`echo $filename_2 | cut -f2 -d ','`
echo "$fx3"
python3 ecn_www.py $fx3
pkill -9 python3
done
done

echo "Finishing the web-server measurement, Thank you."