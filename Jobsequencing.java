import java.util.ArrayList;
import java.util.Collections;
public class Jobsequencing {
static class Job {
int deadline;
int profit;
int id;
public Job(int i,int d,int p) {
id = i;
deadline = d;
profit = p;
}
}
public static void main(String args[]) {
int jobInfo[][] ={{4,20},{1,10},{1,40},{1,30}};
ArrayList&lt;Job&gt; jobs = new ArrayList&lt;&gt;();
for(int i =0; i &lt;jobInfo.length;i++){
// jobs[i] = new Job(i,jobInfo[i][0],jobInfo[i][1]);
jobs.add(new Job(i,jobInfo[i][0],jobInfo[i][1]));
}
Collections.sort(jobs, (a,b) -&gt; b.profit-a.profit);
ArrayList&lt;Integer&gt; seq = new ArrayList&lt;&gt;();
int time = 0;
for(int i = 0; i &lt;jobs.size();i++){
Job curr = jobs.get(i);
if(curr.deadline&gt; time){
seq.add(curr.id);
time++;
}
}
System.err.println("Max jobs = "+ seq.size());
for(int i =0; i &lt;seq.size();i++){
System.err.print(seq.get(i)+" ");
}
System.err.println("");
}
}