echo "Starting generation web site list files using input file : traceroute_ip_list.txt";

## Create files for web site list in websitelist dir
mkdir websitelist

cat traceroute_ip_list.txt | sed -n '1, 2000p' >  websitelist/web_2000.txt
cat traceroute_ip_list.txt | sed -n '2001, 4000p' >  websitelist/web_4000.txt
cat traceroute_ip_list.txt | sed -n '4001, 6000p' >  websitelist/web_6000.txt
cat traceroute_ip_list.txt | sed -n '6001, 8000p' >  websitelist/web_8000.txt
cat traceroute_ip_list.txt | sed -n '8001, 10000p' >  websitelist/web_10000.txt
cat traceroute_ip_list.txt | sed -n '10001, 20000p' >  websitelist/web_20000.txt
cat traceroute_ip_list.txt | sed -n '20001, 30000p' >  websitelist/web_30000.txt
cat traceroute_ip_list.txt | sed -n '30001, 40000p' >  websitelist/web_40000.txt
cat traceroute_ip_list.txt | sed -n '40001, 50000p' >  websitelist/web_50000.txt
cat traceroute_ip_list.txt | sed -n '50001, 60000p' >  websitelist/web_60000.txt
cat traceroute_ip_list.txt | sed -n '60001, 70000p' >  websitelist/web_70000.txt
cat traceroute_ip_list.txt | sed -n '70001, 80000p' >  websitelist/web_80000.txt
cat traceroute_ip_list.txt | sed -n '80001, 90000p' >  websitelist/web_90000.txt
cat traceroute_ip_list.txt | sed -n '90001, 100000p' >  websitelist/web_100000.txt

# for ecn server testing
cat traceroute_ip_list.txt | sed -n '1, 100000p' >  websitelist/web_100000.txt
cat traceroute_ip_list.txt | sed -n '100001, 200000p' >  websitelist/web_200000.txt
cat traceroute_ip_list.txt | sed -n '200001, 300000p' >  websitelist/web_300000.txt
cat traceroute_ip_list.txt | sed -n '300001, 400000p' >  websitelist/web_400000.txt
cat traceroute_ip_list.txt | sed -n '400001, 500000p' >  websitelist/web_500000.txt
cat traceroute_ip_list.txt | sed -n '500001, 600000p' >  websitelist/web_600000.txt
# for testing
cat traceroute_ip_list.txt | sed -n '1, 5p' >  websitelist/web_5.txt
# for adding new website list
cat output.txt | sed -n '1, 20000p' > websitelist/output_20000.txt
cat output.txt | sed -n '20001, 40000p' > websitelist/output_40000.txt
cat output.txt | sed -n '40001, 60000p' > websitelist/output_60000.txt
cat output.txt | sed -n '60001, 80000p' > websitelist/output_80000.txt
cat output.txt | sed -n '80001, 100000p' > websitelist/output_100000.txt
ls websitelist
echo "Finishing the generation, thank you.";
