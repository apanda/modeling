# Note you need gnuplot 4.4 for the pdfcairo terminal.

set terminal pdfcairo font "Gill Sans, 16" linewidth 6 rounded

# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

#set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
# borders are useless and make it harder to see plotted lines near the border.
# Also, put it in grey; no need for so much emphasis on a border.

set xtics nomirror
set ytics nomirror

#set ylabel "# of Storage Nodes"
#set xlabel "# of Disks in Compute Node"
#set bars small
#set datafile separator ","
#set output "storage.pdf"
#plot "data_for_graph_10" index 0 using 1:2 w linespoints lc -1 lt 1 lw 1 title "10 Gbps",\
     #"data_for_graph_10" index 1 using 1:2 w linespoints lc 9 lt 0 lw 1 pt 3 title "40 Gbps"
set ylabel  "Time (seconds)"
set xlabel "# of Branches"
#set xrange [2:110]
#set yrange [0:100]
#set logscale y
set key off
set output "branch_timing.pdf"
plot "branch-timing" using 1:2 w p lc -1 lt 0 lw 1 pt 2
reset
