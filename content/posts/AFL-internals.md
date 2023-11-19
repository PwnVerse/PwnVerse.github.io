+++
title = "AFL Internals"
date = "2021-11-11"
+++

I've been using AFL for quite sometime now, but really wanted to know how it works internally. This blog post is solely meant as a means of documentation for whatever I've learnt and I'd be glad if it helps someone else too.

## The background

AFL is some of the most commonly used fuzzers in the wild. It is a coverage guided fuzzer. I'm not going to discuss what AFL is good at, you can always refer to it's [source](https://github.com/AFLplusplus/AFLplusplus) for knowing that.

We know that AFL is a coverage guided fuzzer , but how exactly does AFL collect coverage?

## Coverage measurements

When you use `afl-gcc` or an instrumentation compiler of that sort , several instrumentation functions are added to the compiled executable for capturing coverage related information. More specifically, the instrumentation injected into compiled programs captures branch (edge)
coverage, along with coarse branch-taken hit counts.

To understand this better , here's the pseudo code in action for capturing branch coverage - 

```
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++; 
prev_location = cur_location >> 1;
```

Let's break this down to understand it better - 

+ The `cur_location` is generated randomly. The reason is to simplify the process of linking complex projects. Another reason why this is needed is that the output of XOR operations which follow need to be distributed uniformly. You might be wondering why this is needed , we will see more about this in a bit.

+ The `shared_mem` array is a 64 KB shared memory region passed to the instrumentation binary by the caller. Every byte set in the output map can be thought of as a hit for a particular branch (branch_src , branch_dst) tuple.

+ The `cur_location ^ prev_location` acts as a unique index to the shared mem responsible for unique hits.

+ The right shift operation in the last line is to preserve the directionality of tuples. Without this , A ^ B would be indistinguishable from B ^ A.

By now you might be wondering if there's a chance for the XOR operation to return the same result over a certain period or in more simpler terms , collision. Keeping this in mind, developers of AFL used the `COMPILE_TIME_RANDOM` to almost make sure that `cur_location` is unique.

Despite of this certainity that the random time provides , there's still a chance of collisions. Here's where the size of the map comes to rescue and is chosen so that collisions are sporadic with almost all of the intended targets, which usually sport between 2k and 10k discoverable
branch points.

Moreover , the size of the map is also small enough to fit into L2 cache which allows the the map to be analyzed in a matter of microseconds on the receiving end.

This form of coverage provides considerably more insight into the execution
path of the program than simple block coverage.

So now that we know how AFL deals with coverage information , we should now look forward to understanding how AFL uses this coverage information to detect new behaviours.

## Detecting new behaviors

The idea is simple, AFL maintains a global map of `<branch_src , branch_dst>` tuples which can can be rapidly compared with individual traces and updated in just a couple of instructions and a simple loop.

When a certain input produces an execution trace containing new tuples (essentially a new code path) , the input file is preserved and routed for additional processing later on. As expected , inputs which do not generate newer tupes are discarded even if the overall control flow sequence is unique. This allows for a more fine-grained and long-term exploration of program state all the while not having to perform any computationally intensive tasks.

To better understand how the algorithm works , lets have a look at the following execution traces - 

```
  #1: A -> B -> C -> D -> E
  #2: A -> B -> C -> A -> E
```

The `#2` trace is considered unique due to the presence of new tuples (CA, AE)

But now that `#2` is processed ,something like the following **wont be recognized as unique** - 

```
#3: A -> B -> C -> A -> B -> C -> A -> B -> C -> D -> E
```

Apart from new tuples , AFL also considers coarse magnitude count for tuple hit rate. This count is divided into several buckets - 

```
1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
```

Changes within a bucket's range are ignored but transition from one bucket to another is flagged as an interesting change in program's control flow.

This hit count behaviour can tell us alot more about potentially interesting control flow changes. As you can guess by now , all these algorithms running under the hoodf of AFL are fairly memory expensive.

Now that we've seen how AFL detects new behaviours , let us also see how AFL optimizes it's fuzzing efforts.

## Culling the corpus

AFL periodically re-evaluates the input queue using a fast algorithm that selects a smaller subset of test cases that still cover every tuple seen so far and whose characterstics make them particularly favourable to the tool.

The algorithm works by assigning every queue entry a score proportional to it's execution policy and file size and then selecting lowest-scoring. The tuples are then processed as follows - 

+ Find next tuple not yet in temporary working set.
+ Locate the winning queue for this tuple.
+ Register all tuples present in that entry's trace in working set.
+ Repeat the above steps if there are any missing tuples in the set.

So what happens with the non-favoured entries? They're discarded? Well , apparently not. AFL doesn't discard non-favoured inputs, but they are skipped with varying probabilities when encountered in the queue : 

+ If there are new yet-to-be-fuzzed favourites in the queue,  all non-favoured entires are discarded.

+ If no new favourites found : 

    1. If current non-favoured entry was fuzzed before, it will be skipped 95% of times.
    2. If it hasn't gone through any fuzzing rounds yet, the odds of skipping drop down to 75%.


Now that we're aware of how the input corpus is selected curatively, we must also see how AFL manages inputs with large and varying sizes.

## Trimming the input files

As you can probably guess , file size has a drastic impact over the overall performence of the fuzzer. This is simply because large files make target binary slower and also because they reduce the likelihood that a mutation would touch important format control structures , rather than any redundant data blocks.

Luckily for us, the instrumentation feedback provides a simple and robust way to automatically trim down input files while ensuring that changes made to the files have no impact on execution path.

The built-in trimmer attempts to sequentially remove blocks of data with variable length. Basically , **any deletion which doesnt effect the checksum of the trace is commited to the disk.**

There's also the standalone `afl-tmin` which provides more exhaustive iterative algorithm to perform normalization on trimmed files. 

The actual minimization technique is : 

1. Attempt to zero large blocks of data with large stepovers.
2. Perform a block detection pass with decreasing block sizes and stepovers - more like binary search.
3. Perform alphabet normalization by counting unique characters and trying to bulk-replace each with zero value.

Now that we have seen how AFL trims and optimizes input files for removing redundant data blocks , we should also have a look at how AFL chooses it's fuzzing strategies.

## Fuzzing strategies

Early on during fuzzing, AFL chooses a fairly deterministic approach, and then progresses to random stacked modifications and test case splicing. The early stages include the following strategies : 

+ Sequential bit flips with varying lengths.
+ Sequential additions and subtraction of small integers.
+ Sequential insertions of known interesting integers (negetive numbers, INT_MAX)

The non-deterministic approaches include stacked bit flips , insertions , deletions , arithmetics and splicing of different test cases.

## Fork server

To improve performence, AFL uses something known as fork-server , where the fuzzed process goes through `execve` , and doing all the linking and initializing only once ; after that it is cloned from stopped process image by leveraging `copy-on-write`.

The way fork-server works is that it simply stops at the first instrumented function to await commands from `afl-fuzz`. 
