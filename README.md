# ecryptfs-stats
Measuring the time ecryptfs consumes in encryption and I/O steps.

# Usage
1.make && insmod && mount

2. Write to ecryptfs: dd if=/dev/zero of=a bs=4K count=100

3. Get the timing results: cat /proc/ecryptfs_time_stat

4. Sum the I/O time or crypto time: tail -n100 /proc/ecryptfs_time_stat | awk '{print $6}' | awk '{sum+=$1} END {print sum}'