echo "Starting ECN web-server measurement using input file : filelist_server.txt";
mkdir ecnserver
fx2=`cat web_300000_json.txt`
for filename_2 in $fx2
do
echo "$filename_2" 
python3 ecn_json.py $filename_2
pkill -9 python3
done
done

# awk 'BEGIN {FS="\"";OFS=","} {print $8,$12}' test.txt > test_2.txt

awk 'BEGIN {FS="\"";OFS=","} $12 == "^[[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}]" {print $0}' test.ndjson
test.ndjson | awk '{match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); ip = substr($0,RSTART,RLENGTH); print ip}'
cat test.csv | awk '$12 == "^[[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}]" { print $0 }'
awk '{match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); print $0}' test.ndjson

awk -F\" '{print $12}'  test.ndjson
awk -F'\"' '$12 ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ {print}' test.ndjson
cat test.ndjson | awk -F'\"' '$12 {print $12}'
awk -F'\"' '$12 ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ {print $0}' test.ndjson
awk -F'\"' '$12 ~ /\([0-9.]\+\)\s.*/\1/p/ {print $12}'

# sed -E 's/\},\s*\{/\},\n\{/g' test.ndjson | grep  '"domain" : '
# sed -E 's/\},\s*\{/\},\n\{/g' test.ndjson
# "domain": "qq.com", "dip": "123.151.137.18"}

# awk -F\" '{print $1}'test.ndjson
# awk -F  "\"" '{print $4,$8,$12}' test.ndjson > test.txt
# awk 'BEGIN {FS="\"";OFS=","} {print $4,$8,$12}' test.ndjson
# awk 'BEGIN {FS="\"";OFS=","} {print $4,$8,$12}' web_300000.ndjson > web_300000_json.txt

# scp -i ~/Documents/Projects/5g_measurement_auto/ssh_key/id_rsa hyoyoung@128.110.219.93:/users/hyoyoung/pathspider_original/examples/web_20000.ndjson ./
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

# fx=`cat filelist_server.txt`
# for filename in $fx
# do
# echo "$filename"
# fx2=`cat $filename`
# for filename_2 in $fx2
# do
# fx3=`echo $filename_2 | cut -f2 -d ','`
# echo "$fx3"
# python3 ecn_www.py $fx3
# pkill -9 python3
# done
# done

echo "Finishing the web-server measurement, Thank you."