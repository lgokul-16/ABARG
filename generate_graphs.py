import matplotlib.pyplot as plt
import numpy as np

# A4 dimensions in inches (standard is 8.27 x 11.69)
A4_WIDTH = 8.27
A4_HEIGHT = 11.69

def create_graphs():
    # Data Categories
    categories = ['Men', 'Women', 'Transgender']
    
    # Placeholder Data (Percentages)
    # Education: Literacy Rate or Higher Education completion
    education_data = [80, 75, 50] 
    
    # Job Opportunities: Employment Rate or Access to Jobs
    job_data = [78, 62, 40] 

    # Create the figure with A4 size
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(A4_WIDTH, A4_HEIGHT))
    
    # Main Title
    fig.suptitle('Social Metrics Comparison', fontsize=20, fontweight='bold', y=0.95)

    # Colors for the bars
    bar_colors = ['#3498db', '#e74c3c', '#9b59b6'] 
    # Blue for Men, Red for Women, Purple for Transgender (Symbolic/Distinct colors)

    # --- Graph 1: Education ---
    bars1 = ax1.bar(categories, education_data, color=bar_colors, edgecolor='black', alpha=0.8)
    ax1.set_title('Comparison of Education Levels', fontsize=16, pad=10)
    ax1.set_ylabel('Percentage / Index', fontsize=12)
    ax1.set_ylim(0, 100)
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add value labels
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{height}%', ha='center', va='bottom', fontsize=11)

    # --- Graph 2: Job Opportunities ---
    bars2 = ax2.bar(categories, job_data, color=bar_colors, edgecolor='black', alpha=0.8)
    ax2.set_title('Comparison of Job Opportunities', fontsize=16, pad=10)
    ax2.set_ylabel('Percentage / Index', fontsize=12)
    ax2.set_ylim(0, 100)
    ax2.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add value labels
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{height}%', ha='center', va='bottom', fontsize=11)

    # Adjust layout to fit A4 well
    plt.tight_layout(rect=[0.05, 0.05, 0.95, 0.93], h_pad=4)
    
    # Save the output
    output_filename = 'gender_comparison_graphs.png'
    plt.savefig(output_filename, dpi=300)
    print(f"Successfully generated {output_filename}")

if __name__ == "__main__":
    create_graphs()
