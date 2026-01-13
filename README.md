#Neural Network Training With Symbolic Gradients (ReLU + Dynamic LR)

This project demonstrates a minimal single-neuron neural network implemented from scratch in Python using:

SymPy for symbolic differentiation

NumPy-like manual forward/backward logic

A manually implemented ReLU activation

A dynamic learning-rate adjustment mechanism

Matplotlib for training visualization

The network has one input, one hidden ReLU neuron, and one output weight. It learns to map an input value x to a target value t.

Features
 Symbolic Gradient Calculation

The derivatives of the loss function

L = (t − y)²


with respect to w1 and w2 are computed using SymPy:

d1 = diff(L, w1)
d2 = diff(L, w2)


These symbolic gradients are substituted with numerical values at every training step.

 Custom ReLU Implementation

ReLU is implemented both symbolically and numerically:

h = z if z > 0 else alpha * z


The alpha parameter sets the negative-slope value (Leaky ReLU).

 Dynamic Learning Rate

The learning rate adjusts during training:

increases by 2% for improvement

halves on overshoot

clipped within a safe range

This allows smoother convergence compared to a fixed LR.

 Early Stopping

Training automatically stops when:

Loss < 1e-6, or

No improvement for p consecutive iterations

 Training Log + Visualization

The script logs:

epoch	w1	w2	lr	h	y	loss

After training, four plots are generated:

Evolution of weight w1

Evolution of weight w2

Learning rate over time

Loss on a logarithmic scale

How It Works

The network performs the following steps per epoch:

Forward pass

Compute loss

Substitute values into symbolic derivatives

Update weights

Adjust learning rate

Store metrics

Early-stopping check

The result is a clean, fully interpretable implementation of gradient descent on a simple ReLU model.

Requirements

Install dependencies:

pip install sympy matplotlib

Usage

Run the script:

python neural_relu_symbolic.py


You will be prompted for:

x (input)

w1 (initial weight 1)

w2 (initial weight 2)

lr (initial learning rate)

t (target value)

Example:

x: 2
w1: 0.5
w2: -1
lr: 0.1
t: 5


The script prints training history and displays graphs.

File Structure
.
├── neural_relu_symbolic.py   # Main script
└── README.md                 # Documentation


A Jupyter notebook version

Just tell me what you want next.
