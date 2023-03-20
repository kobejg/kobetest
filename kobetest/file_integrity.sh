#!/bin/bash
log_date=`date +%Y-%m-%d\_%H:%M:%S -d "9 hour"`
if [[ ! -d /var/log/integrity_log ]]; then
        mkdir /var/log/integrity_log
fi
if [[ ! -d /root/result_log ]]; then
        mkdir /root/result_log
fi
set -x
export PS4='Line $LINENO: '
exec 2> /var/log/integrity_log/log-$log_date
#########################GLOBAL VARIABLE#####################################################################################
file_list=("/etc/passwd" "/etc/hosts" "/etc/group" "/etc/chrony.conf")
append_list=("") #add & delete conf.file
homedir="$HOME/checksum/"
mactime_dir="mactime/"
dump_dir="dump/"
log_dir="log/"
perm_file="origin_perm.txt"
origin_file="origin_checksum.txt"
slack_webhook="{YOUR_SLACK_WEBHOOK_URL}"
meta_data_cnt=`curl -s http://169.254.169.254/ | grep -c "401"`
if [ $meta_data_cnt -gt 0  ]
then
	TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"`
    instance_id=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/instance-id`
else
	instance_id=`curl -s "http://169.254.169.254/latest/meta-data/instance-id"`
fi
##########################GLOBAL VARIABLE####################################################################################

function help {
        echo "Copyright (c) 2022 Leon Jeon. He quit his job T_T"
	echo "This is a script that checks file integrity to comply with PCI-DSS. Do not delete."
        echo "Usage: [-a|d] [files..]"
        echo "  -a      config file append in checksum list file ex) -a /etc/my.cnf and -a \"/etc/my.cnf /etc/passwd\""
        echo "  -d      config file delete in checksum list file ex) -d /etc/my.cnf and -d \"/etc/my.cnf /etc/passwd\""
}
function FILE_POSTFIX {
	echo $1 | awk -F "/" '{print $NF}'
}
function FILE_VALIDATE {
	if [[ ! -d $1 ]]
	then
		#ls $1 2>/dev/null  || { echo -e "Not Found $1\nprogram exit."&& exit 1; }
		[[ -f "$1" ]] || { echo -e "$1 no exist file. \nprogram exit."&& EXIT; }
	else
		echo "$1 is directory."
		echo "program exit."
		EXIT
	fi
	
	if [[ -L $1 ]];
	then
		symlink=1
	fi
	if [[ $2 == "REGISTED_CHECK"  ]]
	then
		if [[ -z `cat $homedir$origin_file | grep $1` ]]
		then
			echo "There is no $1 in the "origin_checksum.txt" file."
			EXIT
		fi
	fi
}
function FILE_DUMP {
	if [[ -d $homedir ]]; then
		if [[ ! -f "$homedir$dump_dir$2" ]]; then
			cat $1 > $homedir$dump_dir$2
		else
			backup_time=`date +%Y-%m-%d\ %H:%M:%S -d "9 hour" | sed 's/ /-/g'`
			mv $homedir$dump_dir$2 $homedir$log_dir$2".bak."$backup_time
			cat $1 > $homedir$dump_dir$2
		fi
	else
		echo "Not found $homedir (FILE_DUMP)"
	fi
}
function ORIGIN_LIST_APPEND {
	if [ -d $homedir ]
	then
		append_list=(${append_list[@]} "${@}")
		for result in ${append_list[@]}; do
			FILE_VALIDATE $result
            flag=`cat $homedir$origin_file | awk -F " " '{ if($2=="'$result'")print $2;}' | wc -l`
			if [ 0 -eq $flag ]; then
				sha256sum $result >> $homedir$origin_file
				file_postfix=`FILE_POSTFIX $result`
                stat $result > $homedir$mactime_dir$file_postfix
				if [[ $symlink -eq 1   ]];then
					ls -al $result | awk -F " " '{print $1,$3,$4,$9}' >> $homedir$perm_file
					symlink=0
				else
					ls -al $result | awk -F " " '{print $1,$3,$4,$NF}' >> $homedir$perm_file
				fi
				FILE_DUMP $result $file_postfix
            	
			else
				echo "This file is already registered."
				EXIT
			fi
		
		done
	else
		echo "Not found $homedir (ORIGIN_LIST_APPEND)"
		EXIT
	fi
}
function ORIGIN_LIST_DELETE {
        if [ -d $homedir ]
        then
            append_list=(${append_list[@]} "${@}")
            for result in ${append_list[@]}; do
				FILE_VALIDATE $result "REGISTED_CHECK"
                 o_line=`cat $homedir$origin_file | grep -n $result | awk -F ":" '{print $1}'`
				p_line=`cat $homedir$perm_file | grep -n $result | awk -F ":" '{print $1}'` 
				sed -i ''$o_line'd' $homedir$origin_file
				sed -i ''$p_line'd' $homedir$perm_file
				file_postfix=`FILE_POSTFIX $result`
				rm -f $homedir$mactime_dir$file_postfix
				rm -f $homedir$dump_dir$file_postfix
			done
        else
                echo "Not found $homedir "
				EXIT
        fi
}
function INTEGRITY_COMPARE {
	if [ -d $homedir ]
	then
		list_count=`cat $homedir$origin_file | wc -l`
		for (( i=1; i <= $list_count; i++ )); do
			origin_value=`cat $homedir$origin_file | awk 'BEGIN{ RS = ""; FS = "\n" } {print $'$i'}'`
			origin_checksum=`echo $origin_value | awk -F " " '{print $1}'`
			origin_file_name=`echo $origin_value | awk -F " " '{print $2}'`
			file_postfix=`FILE_POSTFIX $origin_file_name`
			new_checksum=`sha256sum $origin_file_name | awk -F " " '{print $1}'`
			arr_mtime=`stat $origin_file_name | grep "Modify: " | awk -F " " '{print $2,$3}'`
			mtime=`date +%Y-%m-%d\ %H:%M:%S -d "$arr_mtime 9 hour"`
			if [ $origin_checksum == $new_checksum  ]
			then
				echo "Validation OK!"	
			else
				echo "Validation Failed. ""$origin_file_name"
				echo $file_postfix
				echo $origin_file_name
				DIFF_COMPARE "$file_postfix" "$origin_file_name"
				SLACK_ALERT "파일 변조" "$instance_id" "$origin_file_name" "$mtime" "$a_b4" "$a_a4" "$c_b4" "$c_a4" "$d_b4" "$d_a4"
			    FILE_DUMP "$origin_file_name" "$file_postfix"
				ORIGIN_MACTIME_UPDATE "$origin_file_name" "$file_postfix"
                ORIGIN_CHECKSUM_UPDATE "$origin_file_name" "$origin_checksum" "$new_checksum"	
			fi
		done
	else
		echo "Not found $homedir (CHECKSUM_COMPARE)"
		EXIT
	fi
}
function ORIGIN_CHECKSUM_UPDATE {
	if [ -d $homedir ]
	then
		echo "\n"
		sed -i "s/${2}/${3}/g" $homedir$origin_file
	else
		echo "Not found $homedir (ORIGIN_CHECKSUM_UPDATE)" 
		EXIT
	fi

}
function ORIGIN_MACTIME_UPDATE {
	if [ -d $homedir ]
	then
		stat $1 > $homedir$mactime_dir$2
		ls -al $1 | awk -F " " '{print $1,$3,$4}' >> $homedir$mactime_dir$2
	else
		echo "Not found $homedir (ORIGIN_MACTIME_UPDATE)"
		EXIT
	fi
}
function ORIGIN_PERM_UPDATE {
	if [ -d $homedir ]
	then
		sed -i -e "s@${1}@${2}@g" $homedir$perm_file
	else
		echo "Not found $homedir (ORIGIN_PERM_UPDATE)"
        EXIT
	fi
}
function DIFF_PERM {
	if [ -d $homedir ]
	then
		list_count=`cat $homedir$perm_file | wc -l`
		for (( i=1; i <= $list_count; i++ )); do
			perm_list=`cat $homedir$perm_file | awk 'BEGIN{ RS = ""; FS = "\n" } {print $'$i'}'`	
			p_file_name=`echo $perm_list | awk -F " " '{print $NF}'`
			origin_perm=`echo $perm_list | awk -F " " '{print $1}'`
			origin_owner=`echo $perm_list | awk -F " " '{print $2}'`
			origin_group=`echo $perm_list | awk -F " " '{print $3}'`
			new_perm=`ls -al $p_file_name | awk -F " " '{print $1}'`
			new_owner=`ls -al $p_file_name | awk -F " " '{print $3}'`
			new_group=`ls -al $p_file_name | awk -F " " '{print $4}'`
			new_ctime=`stat $p_file_name | grep "Change:" | awk -F " " '{print $2,$3}'`
			ctime=`date +%Y-%m-%d\ %H:%M:%S -d "$new_ctime 9 hour"`
			if [[ "$origin_perm" != "$new_perm" ]]; then
				b4=$(printf "*Before*\n\`\`\`%s\`\`\`\n" "$origin_perm $origin_owner $origin_group")
				a4=$(printf "*After*\n\`\`\`%s\`\`\`\n" "$new_perm $new_owner $new_group")
				SLACK_ALERT "파일속성 변조" "$instance_id" "$p_file_name" "$ctime" "$b4" "$a4"
				pre_value=`echo $origin_perm $origin_owner $origin_group $p_file_name`
				post_value=`echo $new_perm $new_owner $new_group $p_file_name`
				ORIGIN_PERM_UPDATE "$pre_value" "$post_value"
			fi

						
		done
	else
		echo "Not found $homedir (ORIGIN_MACTIME_UPDATE)"
                EXIT
	fi
}

function DIFF_COMPARE {	
	originfile=$2
	dumpfile=$1
	diff_count=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } {print NF}'`
	if [[ -z $diff_count ]]; then
	#	echo "No forgery or not. Time: "`date +%Y-%m-%d\ %H:%M:%S -d "9 hour"`
		diff_count=0	
	fi
	echo $diff_count
	a_flag=0
	c_flag=0
	d_flag=0
	a_b4=""; a_a4=""; c_b4=""; c_a4=""; d_b4=""; d_a4="";
	for (( i=1; i <= $diff_count; i++ )); do
		[[ `diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$i'}'| grep -c '^[> |< ]\|^---$'` -ne 1 ]] || continue
		
		diff=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$i'}'`
		mod=`echo "$diff" | sed 's/[0-9]\{1,\}\|,//g'`
		len=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+1))'}' | sed "s/^[< \|> ]//g"`
		if [[ ${#len} -eq 1  ]];then
			mod="a" #공백 있으면 append 모드(before 문자열이 아무것도 없을 때 예외처리)
			space_flag=true
		fi

		lines=(`echo "$diff" | sed -e 's/,\|[acd]/ /g'`) # 1,2c3 -> lines=(1 2 3) in arry
		left=`echo "$diff" | sed 's/[,]/ /g' | grep -c "^[0-9]\{1,\} [0-9]\{1,\}"` #1 2c3 -> match!
		right=`echo "$diff" | sed 's/[,]/ /g' | grep -c "[0-9]\{1,\} [0-9]\{1,\}$"` #1c2 3 -> match!
		if [[ `echo ${#lines[@]}` -eq 4 ]];
		then
			b4_start_line=${lines[0]}
			b4_end_line=${lines[1]}
			a4_start_line=${lines[2]}
			a4_end_line=${lines[3]}	
		elif [[ `echo ${#lines[@]}` -eq 3  ]];
		then
			if [[ $left -eq 1  ]];
			then
				b4_start_line=${lines[0]}
				b4_end_line=${lines[1]}
				a4_start_line=${lines[2]}
 		               a4_end_line="" # 값이 없으면 null로 들어감. 만약 값이 Null이면'-1' 계산으로 인해 결과값이 음수로 변경 되 아래 do while문에서 한 번만 실행하고 종료
			elif [[ $right -eq 1 ]];
			then
				b4_start_line=${lines[0]}
                b4_end_line="" # 값이 없으면 null로 들어감. 만약 값이 Null이면'-1' 계산으로 인해 결과값이 음수로 변경 되 아래 do while문에서 한 번만 실행하고 종료
                a4_start_line=${lines[1]}
                a4_end_line=${lines[2]} 
			fi
		else
			b4_start_line=${lines[0]}
			a4_start_line=${lines[1]}
		fi
		case $mod in
			"a") #when append
				a_flag=1
				x=1
				y=1
				if [[ $space_flag == true ]];then # when the result is blank
					a_before+="\tAppend Line ($(($a4_start_line-1+$x))"
					while true ; do
                        [[ $x -lt $(($b4_end_line+1-$b4_start_line)) ]] || break
						x=$((x+1))
					done
					while true ; do
						a_after+="\t"
                        a_after+="Line $(($a4_start_line-1+$y)):"`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+x+1+y))'}' | sed 's/^[> |< ]//g'`"\n"
						[[ $y -lt $(($a4_end_line+1-$a4_start_line)) ]] || break
						y=$((y+1))
					done

					if [[ $y -gt 1 ]]; then
						a_before+="~$(($a4_start_line-1+$y)))\n"
					else
						a_before+=")\n"
					fi
					space_flag=false

				else  # no before state in diff command
					a_before+="\tAppend Line ($(($a4_start_line-1+$x))"
                    while true ; do
						a_after+="\t"
						a_after+="Line $(($a4_start_line-1+$x)):"`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+x))'}' | sed 's/^[> |< ]//g'`"\n"
						[[ $x -lt $(($a4_end_line+1-$a4_start_line)) ]] || break
						x=$((x+1))
					done

					if [[ $x -gt 1 ]];then
						a_before+="~$(($a4_start_line-1+$x)))\n"
					else
						a_before+=")\n"
					fi
				fi
				;;	
	
			"c") #when modify
				c_flag=1
				x=1
				y=1
				while true; do
					c_before+="\tLine $(($b4_start_line-1+$x)):"
					c_before+=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+x))'}' | sed 's/^[> |< ]//g'`"\n"
					[[ $x -lt $(($b4_end_line+1-$b4_start_line)) ]] || break
                   	x=$((x+1))
				done
				while true; do
					c_after+="\tLine $(($a4_start_line-1+$y)):"
               		c_after+=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+x+1+y))'}' | sed 's/^[> |< ]//g'`"\n"
					[[ $y -lt $(($a4_end_line+1-$a4_start_line)) ]] || break
					y=$((y+1))
				done
				;;	
		
			"d") #when delete
				d_flag=1
				x=1
				y=1
				d_after+="\tDelete Line ($(($a4_start_line-1+$x))"
				while true; do
				    d_before+="\tLine $(($a4_start_line-1+$x)):"
				    d_before+=`diff -w "$homedir$dump_dir$dumpfile" "$originfile" | awk 'BEGIN{ RS = ""; FS = "\n" } { print $'$(($i+x))'}' | sed 's/^[> |< ]//g'`"\n" 
					[[ $x -lt $(($b4_end_line+1-$b4_start_line)) ]] || break
					x=$((x+1))
                done
				if [[ $x -gt 1 ]];then
                    d_after+="~$(($a4_start_line-1+$x)))\n"
                else
                    d_after+=")\n"
                fi
                ;;

			esac
		b4_start_line=""
		b4_end_line=""
		a4_start_line=""
		a4_end_line=""
	done
if [[ $a_flag -eq 1 ]];then
	a_b4=$(printf "*Before(append)*\n\`\`\`%s\`\`\`\n" "$a_before")
	a_a4=$(printf "*After(append)*\n\`\`\`%s\`\`\`\n" "$a_after")
fi
if [[ $c_flag -eq 1 ]];then
	c_b4=$(printf "*Before(modify)*\n\`\`\`%s\`\`\`\n" "$c_before")
	c_a4=$(printf "*After(modify)*\n\`\`\`%s\`\`\`\n" "$c_after")
fi
if [[ $d_flag -eq 1 ]]; then
	d_b4=$(printf "*Before(Delete)*\n\`\`\`%s\`\`\`\n" "$d_before")
    d_a4=$(printf "*After(Delete)*\n\`\`\`%s\`\`\`\n" "$d_after")
fi
}

function SLACK_ALERT {
	if [ -d $homedir ]
	then
		a10=${10}
		payloads=$(cat <<-EOF
		{
		"attachments":[
			{
				"fallback":"<!channel> 서버에서 파일변조가 발생 하였습니다. 의도된 작업인지 확인하세요.",
				"pretext":"<!channel> 서버에서 파일변조가 발생 하였습니다. 의도된 작업인지 확인하세요.",
				"color":"#D00000",
				"mrkdwn_in": ["fields"],
				"fields":[
				{
					"title":"$1 :alert:",
					"value":"instance_id: $2\nfile_name: $3\n변조된 시각: $4\n$5\n$6\n$7\n$8\n$9\n$a10",
					"short":false
				}
				]
			}
		]
		}
		EOF
		)
		echo $payloads
		curl -X POST --data-urlencode "payload=$payloads" $slack_webhook
	else
		echo "Not found $homedir (SLACK_ALERT)"
		EXIT
	fi

}
function EXIT {
	chattr -R +i $homedir
	chattr -R +i $homedir$mactime_dir
	chattr -R +i $homedir$dump_dir
	chattr -R +i $homedir$log_dir
	exit 1
}
function CHATTR_UNSET {
    chattr -R -i $homedir
    chattr -R -i $homedir$mactime_dir
    chattr -R -i $homedir$dump_dir
    chattr -R -i $homedir$log_dir

}

#########Init directory create #########
function INIT {
	if [ ! -d $homedir ]
	then	
		mkdir $homedir
		mkdir $homedir$mactime_dir
		mkdir $homedir$dump_dir
		mkdir $homedir$log_dir

		for result in ${file_list[@]}; do
			FILE_VALIDATE $result
			sha256sum $result >> $homedir$origin_file
			file_postfix=`FILE_POSTFIX $result`
			stat $result > $homedir$mactime_dir$file_postfix
			FILE_DUMP $result $file_postfix
			ls -al $result | awk -F " " '{print $1,$3,$4,$NF}' >> $homedir$perm_file		
		done
	else
		CHATTR_UNSET
	fi
}
INIT
while getopts ":a:d:h" opt; do
  case $opt in
    a)
      ORIGIN_LIST_APPEND $OPTARG
      EXIT
      ;;
    d)
      ORIGIN_LIST_DELETE $OPTARG
      EXIT
      ;;
    h)
      help
      EXIT
      ;;
   \?)   # \? is escaped not blob string.
      echo >&2 "ERR: Invalid option: -$OPTARG"
      EXIT
      ;;
    :)
      echo >&2 "ERR: Option -$OPTARG requires an argument."
      EXIT
      ;;
  esac
done

INTEGRITY_COMPARE
DIFF_PERM
EXIT
